// -----------------------------------------------------------------------------
// pqse_core.v - sequencer, memories and engine wiring of the PQSE secure element
// (v1.5: ML-KEM-512 / 768 / 1024 chosen per command).
//
// One instruction at a time: fetch from pqse_ucode, with hiding on draw a fresh
// Fisher-Yates permutation for a shuffled instruction (pqse_perm.v) and wait
// 0..15 random dummy clocks, start one engine, wait until it is idle.
//
// Key size (v1.5): kk = k of the command (2, 3, 4), latched at its start: the
// host's CONFIG choice, or for DECAPS the k of the loaded key (key_k). The
// microcode loops over the polynomials of a vector with two counters, i and j
// (C_LOOP, limit k or a constant); before an instruction starts its engine,
// the sequencer translates its index-dependent fields (ins_x below):
//   - 4-bit logical slot codes (L_SJ0 ... L_ACC1) -> 5-bit physical slots,
//     e.g. L_YJ0 -> 8 + 2j
//   - d codes D_DU / D_DV -> du, dv of k
//   - buffer address modes (AM_*): + 48 i, + 48 k, + DU i, ... lanes
//   - HASH modes (HM_*): XOF bytes (i, j), PRF nonces (i, k + i, 2k) and
//     output length (eta1 = 3 for k = 2), H(ek) and J(z || c) lengths, G's k
// The loop counters and kk have complemented shadows like pc and the state.
// Only one engine is ever active, so every memory port is a plain mux on the
// instruction class, idle engines do not toggle, and peak power stays low.
//
// Memories
//   polynomial RAM  two 1280 x 25 RAMs: even slots (share 0, public data) and
//                   odd slots (share 1), 10 slots each. 24 data bits + even parity.
//   I/O buffer      512 x 64 as two 32-bit halves (the host writes 32-bit words
//                   while the core is idle)
//   seed registers  2 x 64 x 65: one RAM per Boolean share, + parity
//
// Side channels (first order, robust probing model with glitches and
// transitions; the gadget-level proof is scripts/pqse_probe_verify.py):
//   - the two shares of a secret live in different RAMs (polynomial RAM 0 /
//     1, seed RAM 0 / 1) and meet only in registered DOM cross terms or in
//     registers that only an operation revealing a public value loads
//   - between instructions both polynomial-RAM output registers are
//     precharged (RAM 1: zero slot, RAM 0: a public word), and the engines
//     read share 0, a public word, share 1: the read mux never sees the two
//     shares of one coefficient, not even in consecutive clocks
// Fault detection (any of them aborts the command with R_FAULT; pqse_host
// then wipes the keys and counts the fault):
//   - parity error on a polynomial or seed RAM read
//   - the complemented copy of the program counter disagrees with pc
//   - the instruction register's parity bit disagrees with its contents
//   - an engine that was started never reported busy (skipped instruction)
//   - the two copies of the masked comparison result differ (pqse_masked.v)
//   - the two independent masked decodings of m' differ (pqse_io.v, IO_SEQ)
// -----------------------------------------------------------------------------
module pqse_core #(
  parameter MASKED   = 1,
  parameter RAMSTYLE = 0,
  parameter PUF_WIN  = 2048
) (
  input  wire        clk,
  input  wire        rst,
  // command
  input  wire        cmd_start,
  input  wire [7:0]  cmd,
  input  wire [2:0]  cmd_k,        // k of the command (2, 3 or 4; pqse_host.v CONFIG[2:1])
  output reg  [2:0]  key_k,        // k of the loaded key pair
  input  wire        cmd_inj,      // use injected seeds (pqse_host allows it in TEST only)
  input  wire        kexp,         // the shared secret may leave the chip (TEST / PERSO)
  input  wire        hide_en,      // shuffling + random dummy clocks
  output reg         trig,         // measurement trigger: OKINI .. OKCHK (pqse_sys gates it)
  output wire        busy,
  output reg         done,         // one-clock pulse at the end of a command
  output reg  [7:0]  result,
  output reg         key_valid,
  output reg         sk_valid,     // a session key is loaded
  output wire        trng_fail,
  output wire        trng_ok,
  output reg  [31:0] cycles,
  // host buffer access (32-bit words, word address = {lane, half}); idle only
  input  wire        h_we,
  input  wire        h_re,
  input  wire [9:0]  h_addr,
  input  wire [31:0] h_wdata,
  output wire [31:0] h_rdata
);
  `include "pqse_defs.vh"

  // =============================== sequencer ===========================================
  localparam [3:0] Q_IDLE = 4'd0, Q_FETCH = 4'd1, Q_DLY = 4'd2, Q_EXEC = 4'd3,
                   Q_WAIT = 4'd4, Q_RSD = 4'd5, Q_RSW = 4'd6,
                   Q_PG = 4'd7,     // decide: does this instruction need a fresh permutation?
                   Q_PW = 4'd8;     // wait for the Fisher-Yates shuffle (pqse_perm.v)
  reg  [3:0]  q;
  reg  [3:0]  q_n;          // always ~q (fault detection: a flipped state bit could stop the
                            // sequencer in Q_IDLE mid-command, or jump between states)
  reg  [9:0]  pc;           // 1024-entry microcode ROM
  reg  [9:0]  pcn;          // always ~pc (fault detection)
  reg  [95:0] ins_r;
  reg         ins_p;        // parity of ins_r, from the ROM
  wire [95:0] rom_q;
  wire        rom_p = ^rom_q;
  reg         bad, wrap, inj, kx;
  reg         zc;           // the command is ZEROIZE (runs even with a failed TRNG)
  reg         kgc;          // the command generates a key pair (KEYGEN / KGWRAP): PCT
  reg         role;         // session key role: 0 initiator (Encaps), 1 responder (Decaps)
  reg  [63:0] ctr_tx;       // secure messaging: counter of the next message sent
  reg         rx_any;       // secure messaging: a message was accepted with this key
  reg  [63:0] rx_max;       // ... the highest accepted counter
  reg  [63:0] rx_bits;      // ... 64-message replay window: bit k = counter rx_max - k accepted
  wire [63:0] ctr_rx;       // counter of the message being opened (pqse_io.v)
  wire [63:0] rx_sh  = ctr_rx - rx_max;    // newer by
  wire [63:0] rx_age = rx_max - ctr_rx;    // older by
  reg  [3:0]  dly;
  reg  [1:0]  rw;           // reseed: TRNG words collected
  reg [191:0] rseed;
  reg         wfirst;       // first clock of Q_WAIT
  reg         fault;        // a fault was detected during this command
  reg  [2:0]  kk, kk_n;     // k of this command, complemented shadow
  reg  [3:0]  li, lj;       // loop counters (C_LOOP), complemented shadows
  reg  [3:0]  li_n, lj_n;

  // microcode ROM with a registered read (a ROM block on the FPGA): Q_FETCH reads
  // in its first clock (fr = 0) and loads the instruction register in its second
  reg         fr;
  wire        rom_en = (q == Q_FETCH) && !fr;
  pqse_ucode u_rom (.clk(clk), .en(rom_en), .pc(pc), .q(rom_q));

  wire [3:0] cls  = ins_r[95:92];
  wire [2:0] sink = ins_r[30:28];

  // ---- k-dependent sizes and the index translation (v1.5) ----------------------------
  wire       k4   = (kk == 3'd4);
  wire [3:0] du   = k4 ? 4'd11 : 4'd10;               // ciphertext bits per u coefficient
  wire [3:0] dv   = k4 ? 4'd5  : 4'd4;                // ... per v coefficient
  wire [8:0] dul  = k4 ? 9'd44 : 9'd40;               // lanes per u_i (32 du bytes)
  wire [8:0] dvl  = k4 ? 9'd20 : 9'd16;               // lanes of c2
  wire [8:0] k9   = {6'd0, kk};
  wire [8:0] i9   = {5'd0, li}, j9 = {5'd0, lj};
  wire [8:0] x48i = (i9 << 5) + (i9 << 4);            // 48 i
  wire [8:0] x48j = (j9 << 5) + (j9 << 4);
  wire [8:0] x48k = (k9 << 5) + (k9 << 4);
  wire [8:0] xdui = (i9 << 5) + (i9 << 3) + (k4 ? (i9 << 2) : 9'd0);   // 40 i or 44 i
  wire [8:0] xduk = (k9 << 5) + (k9 << 3) + (k4 ? (k9 << 2) : 9'd0);
  wire [7:0] ekl  = x48k[7:0] + 8'd4;                 // ek lanes
  wire [7:0] ctl  = xduk[7:0] + dvl[7:0];             // ciphertext lanes
  wire       eta3 = (kk == 3'd2);                     // eta1 = 3 for ML-KEM-512

  // logical slot code -> physical slot
  function [4:0] ps(input [3:0] c, input [3:0] ii, input [3:0] jj);
    case (c)
      L_SJ0: ps = {jj, 1'b0};             L_SJ1: ps = {jj, 1'b1};
      L_SI0: ps = {ii, 1'b0};             L_SI1: ps = {ii, 1'b1};
      L_YJ0: ps = {jj, 1'b0} + 5'd8;      L_YJ1: ps = {jj, 1'b1} + 5'd8;
      L_YI0: ps = {ii, 1'b0} + 5'd8;      L_YI1: ps = {ii, 1'b1} + 5'd8;
      L_T:   ps = P_T;                    L_Z:   ps = P_Z;
      L_ACC0: ps = P_ACC0;                default: ps = P_ACC1;
    endcase
  endfunction
  function [3:0] dx(input [3:0] d);
    dx = (d == D_DU) ? du : (d == D_DV) ? dv : d;
  endfunction
  function [8:0] bx(input [8:0] ba, input [2:0] am);
    case (am)
      AM_48I: bx = ba + x48i;   AM_48J: bx = ba + x48j;   AM_48K: bx = ba + x48k;
      AM_DUI: bx = ba + xdui;   AM_DUK: bx = ba + xduk;   default: bx = ba;
    endcase
  endfunction

  // POLY: slots straight to the unit
  wire [4:0] p_c = ps(ins_r[86:83], li, lj), p_a = ps(ins_r[82:79], li, lj),
             p_b = ps(ins_r[78:75], li, lj);
  // IO: slot [70:67] + bit 4 in [58], d [85:82], buffer lane [79:71] by mode [57:55]
  wire [4:0] io_sl = ps(ins_r[70:67], li, lj);
  wire [95:0] ins_io = {ins_r[95:86], dx(ins_r[85:82]), ins_r[81:80],
                        bx(ins_r[79:71], ins_r[57:55]), io_sl[3:0], ins_r[66:59], io_sl[4],
                        ins_r[57:0]};
  // MASK: slots [83:80] / [79:76] (+ bit 4 in [56] / [55]) for the ops that use
  // slots (SEL uses the s0 field as a seed entry), d [87:84], lane [74:66] by
  // mode [54:52], eta 3 in [50] for a CBD flagged eta1 ([51]) when k = 2
  wire [3:0] mop    = ins_r[91:88];
  wire       m_sl   = (mop == M_CMPR1) || (mop == M_CMPRC) || (mop == M_CMPRO) ||
                      (mop == M_MU) || (mop == M_CBD);
  wire [4:0] m_s0   = m_sl ? ps(ins_r[83:80], li, lj) : {1'b0, ins_r[83:80]};
  wire [4:0] m_s1   = m_sl ? ps(ins_r[79:76], li, lj) : {1'b0, ins_r[79:76]};
  wire [95:0] ins_mk = {ins_r[95:88], dx(ins_r[87:84]), m_s0[3:0], m_s1[3:0], ins_r[75],
                        bx(ins_r[74:66], ins_r[54:52]), ins_r[65:57], m_s0[4], m_s1[4],
                        ins_r[54:51], ins_r[51] & eta3, ins_r[49:0]};
  // HASH: index modes in [7:4]; sfx [46:31], p1n [75:68], p2n [56:49], onl [19:12]
  wire [3:0]  hm    = ins_r[7:4];
  wire        hprf  = (hm == HM_PI1) || (hm == HM_PKI1) || (hm == HM_PKI2) || (hm == HM_P2K2);
  wire        heta3 = eta3 && ((hm == HM_PI1) || (hm == HM_PKI1));
  wire [7:0]  nonce = (hm == HM_PI1)  ? ins_r[38:31] + {4'd0, li} :
                      (hm == HM_P2K2) ? {4'd0, kk, 1'b0} : {5'd0, kk} + {4'd0, li};
  wire [15:0] h_sfx = (hm == HM_XOF)  ? {4'd0, li, 4'd0, lj} :
                      (hm == HM_XOFT) ? {4'd0, lj, 4'd0, li} :
                      (hm == HM_GK)   ? {13'd0, kk} :
                      hprf            ? {8'd0, nonce} : ins_r[46:31];
  wire [7:0]  h_p1n = (hm == HM_HEK) ? ekl : ins_r[75:68];
  wire [7:0]  h_p2n = (hm == HM_JC)  ? ctl : ins_r[56:49];
  wire [7:0]  h_onl = heta3 ? 8'd24 : ins_r[19:12];
  wire [95:0] ins_hs = {ins_r[95:76], h_p1n, ins_r[67:57], h_p2n, ins_r[48:47], h_sfx,
                        ins_r[30:20], h_onl, ins_r[11:0]};
  wire [4:0]  h_os  = ps(ins_r[11:8], li, lj);         // SNK_SNTT: SampleNTT target slot
  wire       exec = (q == Q_EXEC);
  wire       run  = (q != Q_IDLE);
  assign busy = run | cmd_start;

  // ---- engine busy / start ----
  wire sp_busy, p_busy, io_busy, m_busy, pf_busy, pr_busy;
  wire pr_ferr;                                // PRNG word taken stale (pqse_prng)
  wire p_zfail;                                // ZCHK: two copies of a polynomial differ (pqse_poly)
  wire io_bad, m_bad, m_fault, io_fault;
  wire any_busy = sp_busy | p_busy | io_busy | m_busy | pf_busy;

  wire is_eng   = (cls == C_HASH) || (cls == C_POLY) || (cls == C_IO) ||
                  (cls == C_MASK) || (cls == C_PUF);
  // single-clock masked op (never busy after its start clock)
  wire one_clk  = (cls == C_MASK) && (ins_r[91:88] == M_OKINI);
  wire sp_start = exec && (cls == C_HASH);
  wire p_start  = exec && (cls == C_POLY);
  wire io_start = exec && (cls == C_IO);
  wire pf_start = exec && (cls == C_PUF);
  wire h_strm   = (cls == C_HASH) && ((sink == SNK_MB2A) || (sink == SNK_MCMP));
  wire m_start  = exec && ((cls == C_MASK) || h_strm);
  wire pa_start = exec && (cls == C_HASH) && (sink == SNK_SNTT);
  // (SNK_CBD, the unmasked sampler, is no longer used: every secret polynomial
  //  is sampled masked by pqse_masked.v, so the sampler is not instantiated)

  // ---- shuffling: a fresh random permutation before every shuffled instruction ----
  wire [3:0] iop      = ins_r[91:88];
  wire       pg_need  = hide_en && (
                          ((cls == C_POLY) && (iop != P_ZERO) && (iop != P_ZCHK)) ||
                          ((cls == C_MASK) && ((iop == M_CMPR1) || (iop == M_CMPRC) ||
                                               (iop == M_CMPRO) || (iop == M_MU) || (iop == M_CBD))));
  wire       pg_n64   = (cls == C_POLY) && ((iop == P_NTT) || (iop == P_INTT));
  wire       pg_start = (q == Q_PG) && pg_need;
  wire       pg_busy, pg_rt, pg_next, pg_ready;
  wire [6:0] p_pq, m_pq, pq_val;
  wire [6:0] pq_idx   = (cls == C_POLY) ? p_pq : m_pq;   // one engine at a time
  // (pqse_perm instance below, after the PRNG)

  // the masked unit's instruction for a stream sink: M_STRM, {tag base, kind}, slots, acc
  wire [95:0] m_ins = (cls == C_MASK) ? ins_mk :
                      {C_MASK, M_STRM, 2'd0, ins_r[3] & (sink == SNK_MCMP), (sink == SNK_MCMP),
                       ins_r[11:8], ins_r[7:4], 1'b0, 9'd0, 4'd0, 4'd0, ins_r[3], 57'd0};

  // loop condition (C_LOOP)
  wire [3:0] lp_cnt   = ins_r[91] ? lj : li;
  wire [3:0] lp_lim   = ins_r[90] ? ins_r[77:74] : {1'b0, kk};
  wire       lp_again = (lp_cnt + 4'd1) < lp_lim;

  // branch condition
  reg br_take;
  always @* begin
    case (ins_r[91:88])
      BC_ALWAYS: br_take = 1'b1;
      BC_BAD:    br_take = bad;
      BC_NBAD:   br_take = !bad;
      BC_INJ:    br_take = inj;
      BC_NINJ:   br_take = !inj;
      BC_NOKEY:  br_take = !key_valid;
      BC_WRAP:   br_take = wrap;
      BC_KEXP:   br_take = kx;
      BC_NOSK:   br_take = !sk_valid;
      BC_ROLE:   br_take = role;
      BC_KGEN:   br_take = kgc;
      default:   br_take = 1'b0;
    endcase
  end

  // entry point of a command
  reg [9:0] ep;
  reg       ep_ok;
  always @* begin
    ep_ok = 1'b1;
    case (cmd)
      CMD_KEYGEN, CMD_KGWRAP: ep = EP_KEYGEN;
      CMD_ENCAPS:  ep = EP_ENCAPS;
      CMD_DECAPS:  ep = EP_DECAPS;
      CMD_IMPORT:  ep = EP_IMPORT;
      CMD_ENROLL:  ep = EP_ENROLL;
      CMD_UNWRAP:  ep = EP_UNWRAP;
      CMD_ZEROIZE: ep = EP_ZEROIZE;
      CMD_SEAL:    ep = EP_SEAL;
      CMD_OPEN:    ep = EP_OPEN;
      CMD_PUFRAW:  ep = EP_PUFRAW;
      CMD_TRNGRAW: ep = EP_TRNGRAW;
      default: begin ep = 10'd0; ep_ok = 1'b0; end
    endcase
  end

  // ---- randomness ----
  wire [63:0] rnd;
  wire        t_valid, t_take_sp, t_take_io;
  wire [63:0] t_word;
  wire        t_en_sp, t_en_io;
  wire        rs_take  = (q == Q_RSD) && t_valid && (rw != 2'd3);
  wire        t_take   = rs_take | t_take_sp | t_take_io;
  wire        t_en     = (q == Q_RSD) | t_en_sp | t_en_io;
  wire        pr_reseed = (q == Q_RSD) && (rw == 2'd3);
  // dummy clocks before an engine start; not while pqse_perm draws an NTT layer
  // order in the background (it takes a word every 2 clocks: no room for a third
  // taker, and that instruction is shuffled per layer anyway)
  wire        dly_ok   = hide_en && is_eng && pg_ready;
  wire        dly_take = (q == Q_DLY) && dly_ok && (dly == 4'd0);
  wire        sp_rt, p_rt, io_rt, m_rt, pf_rt, m_hi;
  wire        r_take = sp_rt | p_rt | io_rt | m_rt | pf_rt | dly_take | pg_rt;
  // only the masked unit's SEL takes in consecutive clocks, and it uses only rnd[63:32]
  wire        r_hi   = m_hi && !(sp_rt | p_rt | io_rt | pf_rt | dly_take | pg_rt);

  pqse_trng u_trng (.clk(clk), .rst(rst), .en(t_en), .take(t_take),
                    .word(t_word), .valid(t_valid), .fail(trng_fail), .ok(trng_ok));
  pqse_prng u_prng (.clk(clk), .rst(rst), .masked_en(MASKED != 0), .reseed(pr_reseed),
                    .seed(rseed[159:0]), .busy(pr_busy), .take(r_take), .take_hi(r_hi), .rnd(rnd),
                    .ferr(pr_ferr));
  pqse_perm u_perm (.clk(clk), .rst(rst), .start(pg_start), .n64(pg_n64),
                    .next(pg_next), .busy(pg_busy), .ready(pg_ready),
                    .rnd(rnd), .rnd_take(pg_rt), .idx(pq_idx), .val(pq_val));

  // ---- measurement trigger (board-level TVLA, scripts/pqse_tvla.py board) ----
  // High from M_OKINI to M_OKCHK: in DECAPS that is everything secret (decoding
  // of m', G, J, the masked re-encryption and the comparison), in OPEN / UNWRAP
  // the tag check. Only the TEST lifecycle lets it out of the chip (pqse_sys.v).
  wire is_okini = exec && (cls == C_MASK) && (iop == M_OKINI);
  wire is_okchk = exec && (cls == C_MASK) && (iop == M_OKCHK);
  always @(posedge clk) begin
    if (rst || !run || is_okchk) trig <= 1'b0;
    else if (is_okini)           trig <= 1'b1;
  end

  // ---- fault sources ----
  wire perr;                                   // RAM parity error (below)
  wire perr_k;                                 // Keccak state parity error (pqse_sponge / pqse_keccak)
  wire f_ctl = (q != ~q_n) || (run && ((pcn != ~pc) || ((q == Q_EXEC) && (^ins_r != ins_p)) ||
                                       (kk != ~kk_n) || (li != ~li_n) || (lj != ~lj_n)));
  wire f_eng = (q == Q_WAIT) && wfirst && is_eng && !one_clk && !any_busy;
  wire f_any = f_ctl | f_eng | perr | perr_k | m_fault | io_fault | pr_ferr | p_zfail;

  // clocks of the command: counts while it runs, cleared when the next one starts
  // (its own block with a plain enable: clock-gated while idle)
  wire cyc_clr = rst || (!run && cmd_start && !fault);
  always @(posedge clk)
    if (cyc_clr || run) cycles <= cyc_clr ? 32'd0 : cycles + 32'd1;

  always @(posedge clk) begin
    if (rst) begin
      begin q <= Q_IDLE; q_n <= ~(Q_IDLE); end done <= 1'b0; key_valid <= 1'b0; sk_valid <= 1'b0; result <= 8'd0;
      dly <= 4'd0; bad <= 1'b0; wrap <= 1'b0; inj <= 1'b0; kx <= 1'b0;
      zc <= 1'b0; kgc <= 1'b0; role <= 1'b0; ctr_tx <= 64'd0;
      rx_any <= 1'b0; rx_max <= 64'd0; rx_bits <= 64'd0;
      pc <= 10'd0; pcn <= 10'h3FF; rw <= 2'd0; wfirst <= 1'b0; fault <= 1'b0; ins_p <= 1'b0;
      ins_r <= 96'd0; fr <= 1'b0;
      kk <= 3'd3; kk_n <= ~3'd3; key_k <= 3'd3;
      li <= 4'd0; li_n <= 4'hF; lj <= 4'd0; lj_n <= 4'hF;
    end else begin
      done <= 1'b0;
      if (q != Q_FETCH) fr <= 1'b0;          // a fetch always starts with the ROM read
      if (f_any && (run || (q != ~q_n))) fault <= 1'b1;
      if (fault) begin                         // abort the command
        result <= R_FAULT;
        done   <= 1'b1;
        fault  <= 1'b0;
        begin q      <= Q_IDLE; q_n <= ~(Q_IDLE); end
      end else begin
        case (q)
          Q_IDLE: if (cmd_start) begin
            bad    <= 1'b0;
            wrap   <= (cmd == CMD_KGWRAP);
            inj    <= cmd_inj;
            kx     <= kexp;
            zc     <= (cmd == CMD_ZEROIZE);
            kgc    <= (cmd == CMD_KEYGEN) || (cmd == CMD_KGWRAP);
            // k of the command: the key's for DECAPS, else the host's choice
            kk     <= (cmd == CMD_DECAPS) ? key_k : cmd_k;
            kk_n   <= ~((cmd == CMD_DECAPS) ? key_k : cmd_k);
            li <= 4'd0; li_n <= 4'hF; lj <= 4'd0; lj_n <= 4'hF;
            if (ep_ok) begin
              pc  <= ep;
              pcn <= ~ep;
              begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
            end else begin
              result <= R_UNKNOWN;
              done   <= 1'b1;
            end
          end
          Q_FETCH: begin
            if (!fr) begin                   // ROM read issued this clock
              fr <= 1'b1;
            end else if (trng_fail && !zc) begin      // ZEROIZE must work even then
              fr     <= 1'b0;
              result <= R_RNGFAIL;
              done   <= 1'b1;
              begin q      <= Q_IDLE; q_n <= ~(Q_IDLE); end
            end else begin
              fr    <= 1'b0;
              ins_r <= rom_q;
              ins_p <= rom_p;
              begin q     <= Q_PG; q_n <= ~(Q_PG); end
            end
          end
          Q_PG: begin q <= pg_need ? Q_PW : Q_DLY; q_n <= ~(pg_need ? Q_PW : Q_DLY); end    // pg_start pulses here
          Q_PW: if (!pg_busy) begin q <= Q_DLY; q_n <= ~(Q_DLY); end
          Q_DLY: begin
            if (dly_ok && dly == 4'd0 && rnd[3:0] != 4'd0) begin
              dly <= rnd[3:0];            // 1..15 dummy clocks before the engine starts
            end else if (dly != 4'd0) begin
              dly <= dly - 4'd1;
              if (dly == 4'd1) begin q <= Q_EXEC; q_n <= ~(Q_EXEC); end
            end else begin
              begin q <= Q_EXEC; q_n <= ~(Q_EXEC); end
            end
          end
          Q_EXEC: begin
            case (cls)
              C_END: begin
                result <= ins_r[7:0];
                done   <= 1'b1;
                begin q      <= Q_IDLE; q_n <= ~(Q_IDLE); end
              end
              C_BR: begin
                pc  <= br_take ? ins_r[87:78] : pc + 10'd1;
                pcn <= br_take ? ~ins_r[87:78] : ~(pc + 10'd1);
                begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
              end
              // loop: counter + 1 < limit ? count and jump : clear and fall through
              C_LOOP: begin
                if (lp_again) begin
                  pc  <= ins_r[87:78];
                  pcn <= ~ins_r[87:78];
                  if (ins_r[91]) begin lj <= lj + 4'd1; lj_n <= ~(lj + 4'd1); end
                  else           begin li <= li + 4'd1; li_n <= ~(li + 4'd1); end
                end else begin
                  pc  <= pc + 10'd1;
                  pcn <= ~(pc + 10'd1);
                  if (ins_r[91]) begin lj <= 4'd0; lj_n <= 4'hF; end
                  else           begin li <= 4'd0; li_n <= 4'hF; end
                end
                begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
              end
              C_SET: begin
                case (ins_r[91:88])
                  ST_KEYV: begin key_valid <= 1'b1; key_k <= kk; end
                  ST_KEYC: key_valid <= 1'b0;
                  ST_BADC: bad <= 1'b0;
                  // a new session key restarts the send counter and empties the window
                  ST_SKV:  begin
                    sk_valid <= 1'b1; role <= 1'b0; ctr_tx <= 64'd0;
                    rx_any <= 1'b0; rx_max <= 64'd0; rx_bits <= 64'd0;
                  end
                  ST_SKVR: begin
                    sk_valid <= 1'b1; role <= 1'b1; ctr_tx <= 64'd0;
                    rx_any <= 1'b0; rx_max <= 64'd0; rx_bits <= 64'd0;
                  end
                  ST_SKC:  begin
                    sk_valid <= 1'b0; ctr_tx <= 64'd0;
                    rx_any <= 1'b0; rx_max <= 64'd0; rx_bits <= 64'd0;
                  end
                  ST_TXINC: ctr_tx <= ctr_tx + 64'd1;
                  // accept ctr_rx (pqse_io.v checked it is fresh): slide the window
                  ST_RXACC: begin
                    if (!rx_any) begin
                      rx_any  <= 1'b1;
                      rx_max  <= ctr_rx;
                      rx_bits <= 64'd1;
                    end else if (ctr_rx > rx_max) begin
                      rx_max  <= ctr_rx;
                      rx_bits <= (rx_sh >= 64'd64) ? 64'd1 : ((rx_bits << rx_sh[5:0]) | 64'd1);
                    end else begin
                      rx_bits <= rx_bits | (64'd1 << rx_age[5:0]);
                    end
                  end
                  default: ;
                endcase
                if (ins_r[91:88] == ST_RESEED) begin
                  rw <= 2'd0;
                  begin q  <= Q_RSD; q_n <= ~(Q_RSD); end
                end else begin
                  pc  <= pc + 10'd1;
                  pcn <= ~(pc + 10'd1);
                  begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
                end
              end
              default: begin             // an engine was started this clock
                wfirst <= 1'b1;
                begin q      <= Q_WAIT; q_n <= ~(Q_WAIT); end
              end
            endcase
          end
          Q_WAIT: begin
            wfirst <= 1'b0;
            if (!any_busy) begin
              pc  <= pc + 10'd1;
              pcn <= ~(pc + 10'd1);
              begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
            end
          end
          Q_RSD: begin                    // collect 3 TRNG words, then reseed the PRNG
            if (rw == 2'd3) begin
              begin q <= Q_RSW; q_n <= ~(Q_RSW); end
            end else if (t_valid) begin
              rseed <= {rseed[127:0], t_word};
              rw    <= rw + 2'd1;
            end
          end
          Q_RSW: if (!pr_busy) begin
            pc  <= pc + 10'd1;
            pcn <= ~(pc + 10'd1);
            begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
          end
          default: begin q <= Q_IDLE; q_n <= ~(Q_IDLE); end
        endcase
      end
      if (io_bad | m_bad) bad <= 1'b1;
    end
  end

  // =============================== memories ===========================================
  // ---- polynomial RAM: RAM 0 = even slots, RAM 1 = odd slots, 25-bit words ----
  reg         pm_re, pm_we;
  reg  [11:0] pm_ra, pm_wa;          // {slot (5), word (7)}; RAM = slot[0], row = slot[4:1]
  reg  [23:0] pm_wd;
  wire [24:0] pr0, pr1;
  wire [24:0] pm_wdp = {^pm_wd, pm_wd};
  pqse_ram_1r1w #(.AW(11), .DW(25), .DEPTH(PM_WORDS), .RAMSTYLE(RAMSTYLE)) u_pmem0 (
    .clk(clk), .we(pm_we && !pm_wa[7]), .waddr({pm_wa[11:8], pm_wa[6:0]}),
    .wdata((pm_we && !pm_wa[7]) ? pm_wdp : 25'd0),
    .re(pm_re && !pm_ra[7]), .raddr({pm_ra[11:8], pm_ra[6:0]}), .rdata(pr0));
  pqse_ram_1r1w #(.AW(11), .DW(25), .DEPTH(PM_WORDS), .RAMSTYLE(RAMSTYLE)) u_pmem1 (
    .clk(clk), .we(pm_we && pm_wa[7]), .waddr({pm_wa[11:8], pm_wa[6:0]}),
    .wdata((pm_we && pm_wa[7]) ? pm_wdp : 25'd0),
    .re(pm_re && pm_ra[7]), .raddr({pm_ra[11:8], pm_ra[6:0]}), .rdata(pr1));
  reg         pm_sel, pm_rv;          // which RAM was read, a checked read happened
  // (the precharge reads between instructions are not parity-checked: before
  //  the power-on wipe the RAM holds whatever it powered up with)
  wire        pm_pre = (q == Q_FETCH) || (q == Q_PG);
  always @(posedge clk) begin
    pm_rv <= pm_re && !pm_pre;
    if (pm_re) pm_sel <= pm_ra[7];
  end
  wire [24:0] pm_rdp = pm_sel ? pr1 : pr0;
  wire [23:0] pm_rd  = pm_rdp[23:0];
  wire        perr_p = pm_rv && (^pm_rdp);

  // ---- I/O buffer, two 32-bit halves ----
  reg         cb_re, cb_we;
  reg  [8:0]  cb_ra, cb_wa;
  reg  [63:0] cb_wd;
  wire [31:0] lo_rd, hi_rd;
  wire        b_core = run;
  wire        lo_we  = b_core ? cb_we : (h_we && !h_addr[0]);
  wire        hi_we  = b_core ? cb_we : (h_we &&  h_addr[0]);
  wire [8:0]  b_wa   = b_core ? cb_wa : h_addr[9:1];
  wire [31:0] lo_wd  = b_core ? cb_wd[31:0]  : h_wdata;
  wire [31:0] hi_wd  = b_core ? cb_wd[63:32] : h_wdata;
  wire        b_re   = b_core ? cb_re : h_re;
  wire [8:0]  b_ra   = b_core ? cb_ra : h_addr[9:1];
  pqse_ram_1r1w #(.AW(9), .DW(32), .RAMSTYLE(0)) u_blo (
    .clk(clk), .we(lo_we), .waddr(b_wa), .wdata(lo_wd), .re(b_re), .raddr(b_ra), .rdata(lo_rd));
  pqse_ram_1r1w #(.AW(9), .DW(32), .RAMSTYLE(0)) u_bhi (
    .clk(clk), .we(hi_we), .waddr(b_wa), .wdata(hi_wd), .re(b_re), .raddr(b_ra), .rdata(hi_rd));
  wire [63:0] cb_rd = {hi_rd, lo_rd};
  reg         h_half;
  always @(posedge clk) if (h_re && !b_core) h_half <= h_addr[0];
  assign h_rdata = h_half ? hi_rd : lo_rd;

  // ---- seed registers: one RAM per share, 64 bits + parity ----
  reg         sr_re, sr_we;
  reg  [5:0]  sr_ra, sr_wa;
  reg  [63:0] sr_wd0, sr_wd1;
  wire [64:0] sp0, sp1;
  wire [63:0] sr_rd0, sr_rd1;
  pqse_ram_1r1w #(.AW(6), .DW(65), .RAMSTYLE(1)) u_seed0 (
    .clk(clk), .we(sr_we), .waddr(sr_wa), .wdata({^sr_wd0, sr_wd0}),
    .re(sr_re), .raddr(sr_ra), .rdata(sp0));
  pqse_ram_1r1w #(.AW(6), .DW(65), .RAMSTYLE(1)) u_seed1 (
    .clk(clk), .we(sr_we & (MASKED != 0)), .waddr(sr_wa), .wdata({^sr_wd1, sr_wd1}),
    .re(sr_re & (MASKED != 0)), .raddr(sr_ra), .rdata(sp1));
  assign sr_rd0 = sp0[63:0];
  assign sr_rd1 = (MASKED != 0) ? sp1[63:0] : 64'd0;   // unprotected build: no share-1 RAM
  // per-share parity, registered separately: the two shares of a seed lane
  // never meet in one gate (each check bit is constant 0 unless a fault hit)
  reg         sr_rv, pe0, pe1;
  always @(posedge clk) begin
    sr_rv <= sr_re;
    pe0   <= sr_rv && (^sp0);
    pe1   <= sr_rv && (MASKED != 0) && (^sp1);
  end
  wire        perr_s = pe0 | pe1;
  assign perr = perr_p | perr_s;

  // =============================== engines ============================================
  // ---- operand isolation (low power; ASIC builds define PQSE_LOWPOWER) ----
  // Each engine sees the shared RAM read buses, the PRNG word and the TRNG word
  // only while it is busy (0 otherwise), so an idle engine's arithmetic (the
  // mod-q multipliers on rnd, the adders on the read buses) does not toggle with
  // another engine's traffic. A busy engine sees the buses unchanged. On the
  // FPGA the AND gates would cost LUTs, so it is off there (the enables are
  // constant 1 and synthesis removes the gates).
`ifdef PQSE_LOWPOWER
  wire iso_sp = sp_busy, iso_p = p_busy, iso_io = io_busy, iso_m = m_busy, iso_pf = pf_busy;
`else
  wire iso_sp = 1'b1, iso_p = 1'b1, iso_io = 1'b1, iso_m = 1'b1, iso_pf = 1'b1;
`endif
  wire [63:0] rnd_sp = rnd & {64{iso_sp}}, rnd_p = rnd & {64{iso_p}}, rnd_io = rnd & {64{iso_io}},
              rnd_m  = rnd & {64{iso_m}},  rnd_pf = rnd & {64{iso_pf}};
  wire [63:0] tw_sp  = t_word & {64{iso_sp}}, tw_io = t_word & {64{iso_io}};
  wire [23:0] pm_rd_p  = pm_rd & {24{iso_p}}, pm_rd_io = pm_rd & {24{iso_io}},
              pm_rd_m  = pm_rd & {24{iso_m}};
  wire [63:0] cb_rd_sp = cb_rd & {64{iso_sp}}, cb_rd_io = cb_rd & {64{iso_io}},
              cb_rd_m  = cb_rd & {64{iso_m}},  cb_rd_pf = cb_rd & {64{iso_pf}};
  wire [63:0] sr0_sp = sr_rd0 & {64{iso_sp}}, sr1_sp = sr_rd1 & {64{iso_sp}},
              sr0_io = sr_rd0 & {64{iso_io}}, sr1_io = sr_rd1 & {64{iso_io}},
              sr0_m  = sr_rd0 & {64{iso_m}},  sr1_m  = sr_rd1 & {64{iso_m}},
              sr0_pf = sr_rd0 & {64{iso_pf}}, sr1_pf = sr_rd1 & {64{iso_pf}};

  // ---- sponge + unmasked samplers ----
  wire        sp_sre, sp_swe, sp_bre, sp_bwe;
  wire [5:0]  sp_sra, sp_swa;
  wire [63:0] sp_swd0, sp_swd1, sp_bwd;
  wire [8:0]  sp_bra, sp_bwa;
  wire        so_valid, so_ready;
  wire [63:0] so_v0, so_v1;
  wire        pa_ready, pa_done, pa_we, m_sready;
  wire [11:0] pa_wa;
  wire [23:0] pa_wd;

  assign so_ready = (sink == SNK_SNTT) ? pa_ready : m_sready;
  wire sink_done  = (sink == SNK_SNTT) ? pa_done  : !m_busy;

  pqse_sponge #(.MASKED(MASKED)) u_sponge (
    .clk(clk), .rst(rst), .start(sp_start), .ins(ins_hs), .busy(sp_busy),
    .sr_re(sp_sre), .sr_addr(sp_sra), .sr_d0(sr0_sp), .sr_d1(sr1_sp),
    .sw_we(sp_swe), .sw_addr(sp_swa), .sw_d0(sp_swd0), .sw_d1(sp_swd1),
    .br_re(sp_bre), .br_addr(sp_bra), .br_d(cb_rd_sp),
    .bw_we(sp_bwe), .bw_addr(sp_bwa), .bw_d(sp_bwd),
    .trng_en(t_en_sp), .trng_valid(t_valid), .trng_word(tw_sp), .trng_take(t_take_sp),
    .so_valid(so_valid), .so_v0(so_v0), .so_v1(so_v1), .so_ready(so_ready),
    .samp_done(pa_done), .sink_done(sink_done),
    .rnd(rnd_sp), .rnd_take(sp_rt), .perr(perr_k)
  );

  pqse_parse u_parse (
    .clk(clk), .rst(rst), .start(pa_start), .slot(h_os),
    .in_valid(so_valid && sink == SNK_SNTT), .in_lane(so_v0), .in_ready(pa_ready),
    .done(pa_done), .we(pa_we), .waddr(pa_wa), .wdata(pa_wd));

  // ---- polynomial unit ----
  wire        p_re, p_we;
  wire [11:0] p_ra, p_wa;
  wire [23:0] p_wd;
  pqse_poly u_poly (
    .clk(clk), .rst(rst), .start(p_start), .op_in(ins_r[91:88]), .acc_in(ins_r[87]),
    .c_in(p_c), .a_in(p_a), .b_in(p_b),
    .shuf_in(ins_r[74] & hide_en), .busy(p_busy),
    .re(p_re), .raddr(p_ra), .rdata(pm_rd_p), .we(p_we), .waddr(p_wa), .wdata(p_wd),
    .rnd(rnd_p), .rnd_take(p_rt), .pq_idx(p_pq), .pq_val(pq_val),
    .pq_next(pg_next), .pq_ready(pg_ready), .zfail(p_zfail));

  // ---- I/O unit ----
  wire        io_re, io_we, io_bre, io_bwe, io_sre, io_swe;
  wire [11:0] io_ra, io_wa;
  wire [23:0] io_wd;
  wire [8:0]  io_bra, io_bwa;
  wire [63:0] io_bwd, io_swd0, io_swd1;
  wire [5:0]  io_sra, io_swa;
  pqse_io u_io (
    .clk(clk), .rst(rst), .start(io_start), .ins(ins_io), .busy(io_busy), .bad_set(io_bad),
    .re(io_re), .raddr(io_ra), .rdata(pm_rd_io), .we(io_we), .waddr(io_wa), .wdata(io_wd),
    .bre(io_bre), .braddr(io_bra), .brdata(cb_rd_io), .bwe(io_bwe), .bwaddr(io_bwa), .bwdata(io_bwd),
    .sre(io_sre), .sraddr(io_sra), .srd0(sr0_io), .srd1(sr1_io),
    .swe(io_swe), .swaddr(io_swa), .swd0(io_swd0), .swd1(io_swd1),
    .rnd(rnd_io), .rnd_take(io_rt),
    .t_en(t_en_io), .t_valid(t_valid), .t_word(tw_io), .t_take(t_take_io),
    .ctr_tx(ctr_tx), .rx_any(rx_any), .rx_max(rx_max), .rx_bits(rx_bits), .ctr_rx(ctr_rx),
    .fault_set(io_fault));

  // ---- masked unit ----
  wire        m_re, m_we, m_bre, m_bwe, m_sre, m_swe;
  wire [11:0] m_ra, m_wa;
  wire [23:0] m_wd;
  wire [8:0]  m_bra, m_bwa;
  wire [63:0] m_bwd, m_swd0, m_swd1;
  wire [5:0]  m_sra, m_swa;
  pqse_masked u_masked (
    .clk(clk), .rst(rst), .start(m_start), .ins(m_ins), .busy(m_busy), .bad_set(m_bad),
    .s_valid(so_valid && (sink == SNK_MB2A || sink == SNK_MCMP)), .s_v0(so_v0), .s_v1(so_v1),
    .s_ready(m_sready),
    .re(m_re), .raddr(m_ra), .rdata(pm_rd_m), .we(m_we), .waddr(m_wa), .wdata(m_wd),
    .bre(m_bre), .braddr(m_bra), .brdata(cb_rd_m), .bwe(m_bwe), .bwaddr(m_bwa), .bwdata(m_bwd),
    .sre(m_sre), .sraddr(m_sra), .srd0(sr0_m), .srd1(sr1_m),
    .swe(m_swe), .swaddr(m_swa), .swd0(m_swd0), .swd1(m_swd1),
    .rnd(rnd_m), .rnd_take(m_rt), .rnd_hi(m_hi), .shuf(hide_en), .pq_idx(m_pq), .pq_val(pq_val),
    .fault_set(m_fault));

  // ---- PUF ----
  wire        pf_bre, pf_bwe, pf_sre, pf_swe;
  wire [8:0]  pf_bra, pf_bwa;
  wire [63:0] pf_bwd, pf_swd0, pf_swd1;
  wire [5:0]  pf_sra, pf_swa;
  pqse_puf #(.WIN(PUF_WIN)) u_puf (
    .clk(clk), .rst(rst), .start(pf_start), .ins(ins_r), .busy(pf_busy),
    .bre(pf_bre), .braddr(pf_bra), .brdata(cb_rd_pf), .bwe(pf_bwe), .bwaddr(pf_bwa), .bwdata(pf_bwd),
    .sre(pf_sre), .sraddr(pf_sra), .srd0(sr0_pf), .srd1(sr1_pf),
    .swe(pf_swe), .swaddr(pf_swa), .swd0(pf_swd0), .swd1(pf_swd1),
    .rnd(rnd_pf), .rnd_take(pf_rt));

  // =============================== port multiplexing ===================================
  always @* begin
    pm_re = 1'b0; pm_ra = 12'd0; pm_we = 1'b0; pm_wa = 12'd0; pm_wd = 24'd0;
    cb_re = 1'b0; cb_ra = 9'd0;  cb_we = 1'b0; cb_wa = 9'd0;  cb_wd = 64'd0;
    sr_re = 1'b0; sr_ra = 6'd0;  sr_we = 1'b0; sr_wa = 6'd0;  sr_wd0 = 64'd0; sr_wd1 = 64'd0;
    // Precharge of the two polynomial-RAM output registers between instructions
    // (no engine runs in these clocks): RAM 1 reads the all-zero slot S_Z, RAM 0
    // a public word (S_T word 0). An instruction then never starts with a word
    // of the other share of a coefficient still held behind the read mux.
    if (q == Q_FETCH)   begin pm_re = 1'b1; pm_ra = {P_Z, 7'd0}; end
    else if (q == Q_PG) begin pm_re = 1'b1; pm_ra = {P_T, 7'd0}; end
    else if (run) begin
      case (cls)
        C_HASH: begin
          sr_re = sp_sre; sr_ra = sp_sra;
          sr_we = sp_swe; sr_wa = sp_swa; sr_wd0 = sp_swd0; sr_wd1 = sp_swd1;
          if (sp_bre) begin cb_re = 1'b1; cb_ra = sp_bra; end
          else if (m_bre) begin cb_re = 1'b1; cb_ra = m_bra; end      // tag bits (after absorbing)
          if (sp_bwe) begin cb_we = 1'b1; cb_wa = sp_bwa; cb_wd = sp_bwd; end
          case (sink)
            SNK_SNTT: begin pm_we = pa_we;  pm_wa = pa_wa;  pm_wd = pa_wd;  end
            SNK_MB2A: begin
              pm_re = m_re; pm_ra = m_ra;
              pm_we = m_we; pm_wa = m_wa; pm_wd = m_wd;
            end
            default: ;
          endcase
        end
        C_POLY: begin
          pm_re = p_re; pm_ra = p_ra; pm_we = p_we; pm_wa = p_wa; pm_wd = p_wd;
        end
        C_IO: begin
          pm_re = io_re; pm_ra = io_ra; pm_we = io_we; pm_wa = io_wa; pm_wd = io_wd;
          cb_re = io_bre; cb_ra = io_bra; cb_we = io_bwe; cb_wa = io_bwa; cb_wd = io_bwd;
          sr_re = io_sre; sr_ra = io_sra; sr_we = io_swe; sr_wa = io_swa;
          sr_wd0 = io_swd0; sr_wd1 = io_swd1;
        end
        C_MASK: begin
          pm_re = m_re; pm_ra = m_ra; pm_we = m_we; pm_wa = m_wa; pm_wd = m_wd;
          cb_re = m_bre; cb_ra = m_bra; cb_we = m_bwe; cb_wa = m_bwa; cb_wd = m_bwd;
          sr_re = m_sre; sr_ra = m_sra; sr_we = m_swe; sr_wa = m_swa;
          sr_wd0 = m_swd0; sr_wd1 = m_swd1;
        end
        C_PUF: begin
          cb_re = pf_bre; cb_ra = pf_bra; cb_we = pf_bwe; cb_wa = pf_bwa; cb_wd = pf_bwd;
          sr_re = pf_sre; sr_ra = pf_sra; sr_we = pf_swe; sr_wa = pf_swa;
          sr_wd0 = pf_swd0; sr_wd1 = pf_swd1;
        end
        default: ;
      endcase
    end
  end

`ifdef PQSE_TRACE
  always @(posedge clk) begin
    if (exec) $display("[%0t] pc %0d class %0d k %0d i %0d j %0d ins %h", $time, pc, cls, kk, li, lj, ins_r);
    if (f_any && (run || (q != ~q_n)))
      $display("[%0t] FAULT detected: ctl %b engine %b parity %b keccak %b okchk %b decoder %b prng %b zchk %b",
               $time, f_ctl, f_eng, perr, perr_k, m_fault, io_fault, pr_ferr, p_zfail);
    if (done) $display("[%0t] command done: result %0d, %0d cycles", $time, result, cycles);
  end
`endif
endmodule
