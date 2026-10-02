// -----------------------------------------------------------------------------
// pqse_core.v - sequencer, memories and engine wiring of the PQSE secure element.
//
// One instruction at a time: fetch from pqse_ucode, with hiding on draw a fresh
// Fisher-Yates permutation for a shuffled instruction (pqse_perm.v) and wait
// 0..15 random dummy clocks, start one engine, wait until it is idle.
// Only one engine is ever active, so every memory port is a plain mux on the
// instruction class, idle engines do not toggle, and peak power stays low.
//
// Memories
//   polynomial RAM  two 1024 x 25 RAMs: even slots (share 0, public data) and
//                   odd slots (share 1). 24 data bits + even parity.
//   I/O buffer      512 lanes x 4 16-bit words, as two 1024 x 16 RAMs (even /
//                   odd words; the host writes 32-bit words while the core is idle)
//   seed registers  2 x 256 x 17: one RAM per Boolean share, 16-bit words +
//                   parity (16 entries x 4 lanes x 4 words)
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
                   Q_WAIT = 4'd4,                Q_RSW = 4'd6,   // (5: unused)
                   Q_PG = 4'd7,     // decide: does this instruction need a fresh permutation?
                   Q_PW = 4'd8,     // wait for the Fisher-Yates shuffle (pqse_perm.v)
                   Q_RXS = 4'd9,    // ST_RXACC: slide the replay window, one bit per clock
                   Q_TXI = 4'd10;   // ST_TXINC: send counter + 1, one bit per clock (64 clocks)
  reg  [3:0]  q;
  reg  [9:0]  pc;           // 1024-entry microcode ROM
  reg  [9:0]  pcn;          // always ~pc (fault detection)
  reg  [95:0] ins_r;
  reg         ins_p;        // parity of ins_r, from the ROM
  wire [95:0] rom_q;
  wire        rom_p = ^rom_q;
  reg         bad, wrap, inj, kx;
  reg         zc;           // the command is ZEROIZE (runs even with a failed TRNG)
  reg         role;         // session key role: 0 initiator (Encaps), 1 responder (Decaps)
  reg  [63:0] ctr_tx;       // secure messaging: counter of the next message sent
  reg         rx_any;       // secure messaging: a message was accepted with this key
  reg  [63:0] rx_max;       // ... the highest accepted counter
  reg  [63:0] rx_bits;      // ... 64-message replay window: bit k = counter rx_max - k accepted
  wire [63:0] ctr_rx;       // counter of the message being opened (pqse_io.v)
  wire        rx_new;       // ... newer than rx_max (pqse_io.v, IO_CTRC)
  wire [6:0]  rx_dist;      // ... newer / older by (64: 64 or more)
  reg  [5:0]  rxc;          // Q_RXS: window shifts left / Q_TXI: bits done
  reg         txc;          // Q_TXI: carry
  reg         rxo;          // Q_RXS: an older counter (set its bit) instead of a newer one (shift)
  reg  [3:0]  dly;
  reg         wfirst;       // first clock of Q_WAIT
  reg         fault;        // a fault was detected during this command

  // microcode ROM with a registered read (a ROM block on the FPGA): Q_FETCH reads
  // in its first clock (fr = 0) and loads the instruction register in its second
  reg         fr;
  wire        rom_en = (q == Q_FETCH) && !fr;
  pqse_ucode u_rom (.clk(clk), .en(rom_en), .pc(pc), .q(rom_q));

  wire [3:0] cls  = ins_r[95:92];
  wire [2:0] sink = ins_r[30:28];
  wire       exec = (q == Q_EXEC);
  wire       run  = (q != Q_IDLE);
  assign busy = run | cmd_start;

  // ---- engine busy / start ----
  wire sp_busy, p_busy, io_busy, m_busy, pf_busy, pr_busy;
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
                          ((cls == C_POLY) && (iop != P_ZERO)) ||
                          ((cls == C_MASK) && ((iop == M_CMPR1) || (iop == M_CMPRC) ||
                                               (iop == M_CMPRO) || (iop == M_MU) || (iop == M_CBD))));
  wire       pg_n64   = (cls == C_POLY) && ((iop == P_NTT) || (iop == P_INTT));
  wire       pg_start = (q == Q_PG) && pg_need;
  wire       pg_busy, pg_rt, pg_next, pg_ready;
  wire [6:0] p_pq, m_pq, pq_val;
  wire [6:0] pq_idx   = (cls == C_POLY) ? p_pq : m_pq;   // one engine at a time
  // (pqse_perm instance below, after the PRNG)

  // the masked unit's instruction for a stream sink: M_STRM, {tag base, kind}, slots, acc
  wire [95:0] m_ins = (cls == C_MASK) ? ins_r :
                      {C_MASK, M_STRM, 2'd0, ins_r[3] & (sink == SNK_MCMP), (sink == SNK_MCMP),
                       ins_r[11:8], ins_r[7:4], 1'b0, 9'd0, 4'd0, 4'd0, ins_r[3], 57'd0};

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
  // ST_RESEED: the PRNG loads its key and IV straight from 3 TRNG words
  wire        pr_ten, pr_take;
  wire        pr_reseed = exec && (cls == C_SET) && (ins_r[91:88] == ST_RESEED);
  wire        t_take   = pr_take | t_take_sp | t_take_io;
  wire        t_en     = pr_ten | t_en_sp | t_en_io;
  // dummy clocks before an engine start; not while pqse_perm draws an NTT layer
  // order in the background (it takes a word every 3 clocks, and a word is fully
  // fresh only 2 clocks after a take: no room for another taker; that
  // instruction is shuffled per layer anyway)
  wire        dly_ok   = hide_en && is_eng && pg_ready;
  wire        dly_take = (q == Q_DLY) && dly_ok && (dly == 4'd0);
  wire        sp_rt, p_rt, io_rt, m_rt, pf_rt, m_hi;
  wire        r_take = sp_rt | p_rt | io_rt | m_rt | pf_rt | dly_take | pg_rt;
  // only the masked unit's SEL takes in consecutive clocks, and it uses only rnd[63:32]
  wire        r_hi   = m_hi && !(sp_rt | p_rt | io_rt | pf_rt | dly_take | pg_rt);

  pqse_trng u_trng (.clk(clk), .rst(rst), .en(t_en), .take(t_take),
                    .word(t_word), .valid(t_valid), .fail(trng_fail), .ok(trng_ok));
  pqse_prng u_prng (.clk(clk), .rst(rst), .masked_en(MASKED != 0), .reseed(pr_reseed),
                    .seed_en(pr_ten), .seed_valid(t_valid), .seed(t_word), .seed_take(pr_take),
                    .busy(pr_busy), .take(r_take), .take_hi(r_hi), .rnd(rnd));
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
  wire f_ctl = run && ((pcn != ~pc) || ((q == Q_EXEC) && (^ins_r != ins_p)));
  wire f_eng = (q == Q_WAIT) && wfirst && is_eng && !one_clk && !any_busy;
  wire f_any = f_ctl | f_eng | perr | m_fault | io_fault;

  always @(posedge clk) begin
    if (rst) begin
      q <= Q_IDLE; done <= 1'b0; key_valid <= 1'b0; sk_valid <= 1'b0; result <= 8'd0;
      cycles <= 32'd0; dly <= 4'd0; bad <= 1'b0; wrap <= 1'b0; inj <= 1'b0; kx <= 1'b0;
      zc <= 1'b0; role <= 1'b0; ctr_tx <= 64'd0;
      rx_any <= 1'b0; rx_max <= 64'd0; rx_bits <= 64'd0;
      pc <= 10'd0; pcn <= 10'h3FF; wfirst <= 1'b0; fault <= 1'b0; ins_p <= 1'b0;
      ins_r <= 96'd0; fr <= 1'b0;
    end else begin
      done <= 1'b0;
      if (q != Q_FETCH) fr <= 1'b0;          // a fetch always starts with the ROM read
      if (run) cycles <= cycles + 32'd1;
      if (f_any && run) fault <= 1'b1;
      if (fault) begin                         // abort the command
        result <= R_FAULT;
        done   <= 1'b1;
        fault  <= 1'b0;
        q      <= Q_IDLE;
      end else begin
        case (q)
          Q_IDLE: if (cmd_start) begin
            bad    <= 1'b0;
            wrap   <= (cmd == CMD_KGWRAP);
            inj    <= cmd_inj;
            kx     <= kexp;
            zc     <= (cmd == CMD_ZEROIZE);
            cycles <= 32'd0;
            if (ep_ok) begin
              pc  <= ep;
              pcn <= ~ep;
              q   <= Q_FETCH;
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
              q      <= Q_IDLE;
            end else if (!any_busy) begin    // (after an abort: until the engine still
              fr    <= 1'b0;                 //  running has finished; the engines read ins_r)
              ins_r <= rom_q;
              ins_p <= rom_p;
              q     <= Q_PG;
            end
          end
          Q_PG: q <= pg_need ? Q_PW : Q_DLY;    // pg_start pulses here
          Q_PW: if (!pg_busy) q <= Q_DLY;
          Q_DLY: begin
            if (dly_ok && dly == 4'd0 && rnd[3:0] != 4'd0) begin
              dly <= rnd[3:0];            // 1..15 dummy clocks before the engine starts
            end else if (dly != 4'd0) begin
              dly <= dly - 4'd1;
              if (dly == 4'd1) q <= Q_EXEC;
            end else begin
              q <= Q_EXEC;
            end
          end
          Q_EXEC: begin
            case (cls)
              C_END: begin
                result <= ins_r[7:0];
                done   <= 1'b1;
                q      <= Q_IDLE;
              end
              C_BR: begin
                pc  <= br_take ? ins_r[87:78] : pc + 10'd1;
                pcn <= br_take ? ~ins_r[87:78] : ~(pc + 10'd1);
                q   <= Q_FETCH;
              end
              C_SET: begin
                case (ins_r[91:88])
                  ST_KEYV: key_valid <= 1'b1;
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
                  ST_TXINC: begin rxc <= 6'd0; txc <= 1'b1; end   // (Q_TXI)
                  // accept ctr_rx (pqse_io.v checked it is fresh and measured
                  // how far it is from rx_max): slide the window. A newer counter
                  // shifts the window by its distance, one bit per clock (Q_RXS)
                  ST_RXACC: begin
                    if (!rx_any || (rx_new && rx_dist[6])) begin
                      rx_any  <= 1'b1;
                      rx_max  <= ctr_rx;
                      rx_bits <= 64'd1;
                    end else if (rx_new) begin
                      rx_max  <= ctr_rx;
                      rxc     <= rx_dist[5:0];
                      rxo     <= 1'b0;
                    end else begin
                      rxc     <= 6'd0;          // older: bit rx_dist := 1 by rotation (Q_RXS)
                      rxo     <= 1'b1;
                    end
                  end
                  default: ;
                endcase
                if (ins_r[91:88] == ST_RESEED) begin
                  q  <= Q_RSW;                // pr_reseed pulses in this clock
                end else if (ins_r[91:88] == ST_RXACC && rx_any && !(rx_new && rx_dist[6])) begin
                  q  <= Q_RXS;
                end else if (ins_r[91:88] == ST_TXINC) begin
                  q  <= Q_TXI;
                end else begin
                  pc  <= pc + 10'd1;
                  pcn <= ~(pc + 10'd1);
                  q   <= Q_FETCH;
                end
              end
              default: begin             // an engine was started this clock
                wfirst <= 1'b1;
                q      <= Q_WAIT;
              end
            endcase
          end
          Q_WAIT: begin
            wfirst <= 1'b0;
            if (!any_busy) begin
              pc  <= pc + 10'd1;
              pcn <= ~(pc + 10'd1);
              q   <= Q_FETCH;
            end
          end
          Q_RSW: if (!pr_busy) begin      // the PRNG takes 3 TRNG words and initializes
            pc  <= pc + 10'd1;
            pcn <= ~(pc + 10'd1);
            q   <= Q_FETCH;
          end
          // ctr_tx + 1, bit-serial: rotate right through a half adder, 64 clocks
          // (no 64-bit incrementer; SEAL only)
          Q_TXI: begin
            ctr_tx <= {ctr_tx[0] ^ txc, ctr_tx[63:1]};
            txc    <= ctr_tx[0] & txc;
            rxc    <= rxc + 6'd1;
            if (rxc == 6'd63) begin
              pc  <= pc + 10'd1;
              pcn <= ~(pc + 10'd1);
              q   <= Q_FETCH;
            end
          end
          // newer counter: rx_bits << rx_dist, then bit 0 := 1 (ctr_rx); older:
          // rotate right 64 times, bit 0 being the original bit rxc, and set it
          // when rxc = rx_dist (no 64-way decoder)
          Q_RXS: if (rxo) begin
            rxc     <= rxc + 6'd1;
            rx_bits <= {rx_bits[0] | (rxc == rx_dist[5:0]), rx_bits[63:1]};
            if (rxc == 6'd63) begin
              pc  <= pc + 10'd1;
              pcn <= ~(pc + 10'd1);
              q   <= Q_FETCH;
            end
          end else begin
            rxc     <= rxc - 6'd1;
            rx_bits <= {rx_bits[62:0], (rxc == 6'd1)};
            if (rxc == 6'd1) begin
              pc  <= pc + 10'd1;
              pcn <= ~(pc + 10'd1);
              q   <= Q_FETCH;
            end
          end
          default: q <= Q_IDLE;
        endcase
      end
      if (io_bad | m_bad) bad <= 1'b1;
    end
  end

  // =============================== memories ===========================================
  // ---- polynomial RAM: RAM 0 = even slots, RAM 1 = odd slots, 25-bit words ----
  reg         pm_re, pm_we;
  reg  [10:0] pm_ra, pm_wa;          // {slot, word}
  reg  [23:0] pm_wd;
  wire [24:0] pr0, pr1;
  wire [24:0] pm_wdp = {^pm_wd, pm_wd};
  pqse_ram_1r1w #(.AW(10), .DW(25), .RAMSTYLE(RAMSTYLE)) u_pmem0 (
    .clk(clk), .we(pm_we && !pm_wa[7]), .waddr({pm_wa[10:8], pm_wa[6:0]}),
    .wdata((pm_we && !pm_wa[7]) ? pm_wdp : 25'd0),
    .re(pm_re && !pm_ra[7]), .raddr({pm_ra[10:8], pm_ra[6:0]}), .rdata(pr0));
  pqse_ram_1r1w #(.AW(10), .DW(25), .RAMSTYLE(RAMSTYLE)) u_pmem1 (
    .clk(clk), .we(pm_we && pm_wa[7]), .waddr({pm_wa[10:8], pm_wa[6:0]}),
    .wdata((pm_we && pm_wa[7]) ? pm_wdp : 25'd0),
    .re(pm_re && pm_ra[7]), .raddr({pm_ra[10:8], pm_ra[6:0]}), .rdata(pr1));
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

  // ---- I/O buffer: 16-bit words (v5), lane l word k at {l, k}; two RAMs, even
  // and odd words, so a host 32-bit word ({lane, half}) is one address of both ----
  reg         cb_re, cb_we;
  reg  [10:0] cb_ra, cb_wa;          // {lane, word}
  reg  [15:0] cb_wd;
  wire [15:0] ev_rd, od_rd;
  wire        b_core = run;
  wire        ev_we  = b_core ? (cb_we && !cb_wa[0]) : h_we;
  wire        od_we  = b_core ? (cb_we &&  cb_wa[0]) : h_we;
  wire [9:0]  b_wa   = b_core ? cb_wa[10:1] : h_addr;
  wire [15:0] ev_wd  = b_core ? cb_wd : h_wdata[15:0];
  wire [15:0] od_wd  = b_core ? cb_wd : h_wdata[31:16];
  wire        b_re   = b_core ? cb_re : h_re;
  wire [9:0]  b_ra   = b_core ? cb_ra[10:1] : h_addr;
  pqse_ram_1r1w #(.AW(10), .DW(16), .RAMSTYLE(2)) u_blo (
    .clk(clk), .we(ev_we), .waddr(b_wa), .wdata(ev_wd), .re(b_re), .raddr(b_ra), .rdata(ev_rd));
  pqse_ram_1r1w #(.AW(10), .DW(16), .RAMSTYLE(2)) u_bhi (
    .clk(clk), .we(od_we), .waddr(b_wa), .wdata(od_wd), .re(b_re), .raddr(b_ra), .rdata(od_rd));
  reg         cb_sel;                // the word the core read last: odd
  always @(posedge clk) if (b_re && b_core) cb_sel <= cb_ra[0];
  wire [15:0] cb_rd = cb_sel ? od_rd : ev_rd;
  assign h_rdata = {od_rd, ev_rd};

  // ---- seed registers: one RAM per share, 16-bit words + parity (v5), word
  // address {entry, lane, word} ----
  reg         sr_re, sr_we;
  reg  [7:0]  sr_ra, sr_wa;
  reg  [15:0] sr_wd0, sr_wd1;
  wire [16:0] sp0, sp1;
  wire [15:0] sr_rd0, sr_rd1;
  pqse_ram_1r1w #(.AW(8), .DW(17), .RAMSTYLE(1)) u_seed0 (
    .clk(clk), .we(sr_we), .waddr(sr_wa), .wdata({^sr_wd0, sr_wd0}),
    .re(sr_re), .raddr(sr_ra), .rdata(sp0));
  // share 1 lives at the complemented address: the two share RAMs then have
  // different address nets, so synthesis cannot pack them into one block RAM
  // (GowinSynthesis did: 2 x 17 bits fit one 36-bit-wide BSRAM), and the shares
  // keep separate RAM blocks
  (* keep = 1 *) wire [7:0] sr_ra1 /* synthesis syn_keep = 1 */;
  (* keep = 1 *) wire [7:0] sr_wa1 /* synthesis syn_keep = 1 */;
  assign sr_ra1 = ~sr_ra;
  assign sr_wa1 = ~sr_wa;
  pqse_ram_1r1w #(.AW(8), .DW(17), .RAMSTYLE(1)) u_seed1 (
    .clk(clk), .we(sr_we & (MASKED != 0)), .waddr(sr_wa1), .wdata({^sr_wd1, sr_wd1}),
    .re(sr_re & (MASKED != 0)), .raddr(sr_ra1), .rdata(sp1));
  assign sr_rd0 = sp0[15:0];
  assign sr_rd1 = (MASKED != 0) ? sp1[15:0] : 16'd0;   // unprotected build: no share-1 RAM
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
  // ---- sponge + unmasked samplers ----
  wire        sp_sre, sp_swe, sp_bre, sp_bwe;
  wire [7:0]  sp_sra, sp_swa;
  wire [15:0] sp_swd0, sp_swd1, sp_bwd;
  wire [10:0] sp_bra, sp_bwa;
  wire        so_valid, so_ready;
  wire [15:0] so_v0, so_v1;
  wire        pa_ready, pa_done, pa_we, m_sready;
  wire [10:0] pa_wa;
  wire [23:0] pa_wd;

  assign so_ready = (sink == SNK_SNTT) ? pa_ready : m_sready;
  wire sink_done  = (sink == SNK_SNTT) ? pa_done  : !m_busy;

  pqse_sponge #(.MASKED(MASKED)) u_sponge (
    .clk(clk), .rst(rst), .start(sp_start), .ins(ins_r), .busy(sp_busy),
    .sr_re(sp_sre), .sr_addr(sp_sra), .sr_d0(sr_rd0), .sr_d1(sr_rd1),
    .sw_we(sp_swe), .sw_addr(sp_swa), .sw_d0(sp_swd0), .sw_d1(sp_swd1),
    .br_re(sp_bre), .br_addr(sp_bra), .br_d(cb_rd),
    .bw_we(sp_bwe), .bw_addr(sp_bwa), .bw_d(sp_bwd),
    .trng_en(t_en_sp), .trng_valid(t_valid), .trng_word(t_word), .trng_take(t_take_sp),
    .so_valid(so_valid), .so_v0(so_v0), .so_v1(so_v1), .so_ready(so_ready),
    .samp_done(pa_done), .sink_done(sink_done),
    .rnd(rnd), .rnd_take(sp_rt)
  );

  pqse_parse u_parse (
    .clk(clk), .rst(rst), .start(pa_start), .slot(ins_r[11:8]),
    .in_valid(so_valid && sink == SNK_SNTT), .in_word(so_v0), .in_ready(pa_ready),
    .done(pa_done), .we(pa_we), .waddr(pa_wa), .wdata(pa_wd));

  // ---- polynomial unit ----
  wire        p_re, p_we;
  wire [10:0] p_ra, p_wa;
  wire [23:0] p_wd;
  pqse_poly u_poly (
    .clk(clk), .rst(rst), .start(p_start), .op_in(ins_r[91:88]), .acc_in(ins_r[87]),
    .c_in(ins_r[86:83]), .a_in(ins_r[82:79]), .b_in(ins_r[78:75]),
    .shuf_in(ins_r[74] & hide_en), .busy(p_busy),
    .re(p_re), .raddr(p_ra), .rdata(pm_rd), .we(p_we), .waddr(p_wa), .wdata(p_wd),
    .rnd(rnd), .rnd_take(p_rt), .pq_idx(p_pq), .pq_val(pq_val),
    .pq_next(pg_next), .pq_ready(pg_ready));

  // ---- I/O unit ----
  wire        io_re, io_we, io_bre, io_bwe, io_sre, io_swe;
  wire [10:0] io_ra, io_wa;
  wire [23:0] io_wd;
  wire [10:0] io_bra, io_bwa;
  wire [15:0] io_bwd, io_swd0, io_swd1;
  wire [7:0]  io_sra, io_swa;
  pqse_io u_io (
    .clk(clk), .rst(rst), .start(io_start), .ins(ins_r), .busy(io_busy), .bad_set(io_bad),
    .re(io_re), .raddr(io_ra), .rdata(pm_rd), .we(io_we), .waddr(io_wa), .wdata(io_wd),
    .bre(io_bre), .braddr(io_bra), .brdata(cb_rd), .bwe(io_bwe), .bwaddr(io_bwa), .bwdata(io_bwd),
    .sre(io_sre), .sraddr(io_sra), .srd0(sr_rd0), .srd1(sr_rd1),
    .swe(io_swe), .swaddr(io_swa), .swd0(io_swd0), .swd1(io_swd1),
    .rnd(rnd), .rnd_take(io_rt),
    .t_en(t_en_io), .t_valid(t_valid), .t_word(t_word), .t_take(t_take_io),
    .ctr_tx(ctr_tx), .rx_any(rx_any), .rx_max(rx_max), .rx_bits(rx_bits), .ctr_rx(ctr_rx),
    .rx_new(rx_new), .rx_dist(rx_dist),
    .fault_set(io_fault));

  // ---- masked unit ----
  wire        m_re, m_we, m_bre, m_bwe, m_sre, m_swe;
  wire [10:0] m_ra, m_wa;
  wire [23:0] m_wd;
  wire [10:0] m_bra, m_bwa;
  wire [15:0] m_bwd, m_swd0, m_swd1;
  wire [7:0]  m_sra, m_swa;
  pqse_masked u_masked (
    .clk(clk), .rst(rst), .start(m_start), .ins(m_ins), .busy(m_busy), .bad_set(m_bad),
    .s_valid(so_valid && (sink == SNK_MB2A || sink == SNK_MCMP)), .s_v0(so_v0), .s_v1(so_v1),
    .s_ready(m_sready),
    .re(m_re), .raddr(m_ra), .rdata(pm_rd), .we(m_we), .waddr(m_wa), .wdata(m_wd),
    .bre(m_bre), .braddr(m_bra), .brdata(cb_rd), .bwe(m_bwe), .bwaddr(m_bwa), .bwdata(m_bwd),
    .sre(m_sre), .sraddr(m_sra), .srd0(sr_rd0), .srd1(sr_rd1),
    .swe(m_swe), .swaddr(m_swa), .swd0(m_swd0), .swd1(m_swd1),
    .rnd(rnd), .rnd_take(m_rt), .rnd_hi(m_hi), .shuf(hide_en), .pq_idx(m_pq), .pq_val(pq_val),
    .fault_set(m_fault));

  // ---- PUF ----
  wire        pf_bre, pf_bwe, pf_sre, pf_swe;
  wire [10:0] pf_bra, pf_bwa;
  wire [15:0] pf_bwd, pf_swd0, pf_swd1;
  wire [7:0]  pf_sra, pf_swa;
  pqse_puf #(.WIN(PUF_WIN)) u_puf (
    .clk(clk), .rst(rst), .start(pf_start), .ins(ins_r), .busy(pf_busy),
    .bre(pf_bre), .braddr(pf_bra), .brdata(cb_rd), .bwe(pf_bwe), .bwaddr(pf_bwa), .bwdata(pf_bwd),
    .sre(pf_sre), .sraddr(pf_sra), .srd0(sr_rd0), .srd1(sr_rd1),
    .swe(pf_swe), .swaddr(pf_swa), .swd0(pf_swd0), .swd1(pf_swd1),
    .rnd(rnd), .rnd_take(pf_rt));

  // =============================== port multiplexing ===================================
  always @* begin
    pm_re = 1'b0; pm_ra = 11'd0; pm_we = 1'b0; pm_wa = 11'd0; pm_wd = 24'd0;
    cb_re = 1'b0; cb_ra = 11'd0; cb_we = 1'b0; cb_wa = 11'd0; cb_wd = 16'd0;
    sr_re = 1'b0; sr_ra = 8'd0;  sr_we = 1'b0; sr_wa = 8'd0;  sr_wd0 = 16'd0; sr_wd1 = 16'd0;
    // Precharge of the two polynomial-RAM output registers between instructions
    // (no engine runs in these clocks): RAM 1 reads the all-zero slot S_Z, RAM 0
    // a public word (S_T word 0). An instruction then never starts with a word
    // of the other share of a coefficient still held behind the read mux.
    if (q == Q_FETCH)   begin pm_re = 1'b1; pm_ra = {S_Z, 7'd0}; end
    else if (q == Q_PG) begin pm_re = 1'b1; pm_ra = {S_T, 7'd0}; end
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
    if (exec) $display("[%0t] pc %0d class %0d ins %h", $time, pc, cls, ins_r);
    if (f_any && run) $display("[%0t] FAULT detected: ctl %b engine %b parity %b okchk %b decoder %b",
                               $time, f_ctl, f_eng, perr, m_fault, io_fault);
    if (done) $display("[%0t] command done: result %0d, %0d cycles", $time, result, cycles);
  end
`endif
endmodule
