// -----------------------------------------------------------------------------
// pqse_io.v - I/O unit of the PQSE secure element (public data only).
//
//   DEC     ByteDecode_d from buffer lanes into a slot, bit-serial (d + 1 clocks
//           per coefficient).
//           Optional Decompress_d (d < 12); d = 12 reduces mod q and, with
//           modchk, sets BAD for any value >= q (the ek modulus check).
//           Modes: WR (write), ADD (slot += value), RSUB (slot = value - slot),
//           CHK (check only, no write).
//   ENC     slot -> optional Compress_d -> ByteEncode_d into buffer lanes,
//           bit-serial (Encaps only: the masked Decaps never
//           encodes secrets; it compares in pqse_masked.v)
//   S2B     seed entry (4 lanes, or lanes 0..d-1 when d != 0; shares XORed) ->
//           buffer                                   (unmask: public results)
//   B2S     buffer -> seed entry (share 0; share 1 = 0)
//   S2S     seed entry -> seed entry2 (both shares)
//   SZERO   seed entry := 0
//   SREMASK seed entry := (s0 ^ R, s1 ^ R), R fresh per lane (masks a value
//           that arrived unmasked, e.g. z from the TRNG)
//   SCMP    BAD := (seed entry != buffer lanes), lanes 0..3, or only lanes
//           0..d-1 when d != 0                       (dk hash check, PUF check value)
//   T2B     136 raw TRNG words -> buffer             (TEST only)
//   CTRW    message header lanes 0, 2, 3 := send counter, 0, 0 (lane 1, the
//           message length, is the host's)                               (SEAL)
//   CTRC    BAD := the header counter was already accepted or is older than
//           the 64-message replay window; also hands pqse_core the window
//           update (rx_new, rx_dist) for ST_RXACC                        (OPEN)
//   TRUNC   message length L = header lane 1: BAD unless 1 <= L <= 128;
//           else the bytes from L on of the 16 message lanes := 0  (SEAL, OPEN);
//           cmp = 1: the length check only, nothing is written
//   SEQ     FAULT := the masked values in seed entries e and e2 differ, found
//           without unmasking either: d_s = e_s ^ e2_s per share, registered,
//           then d_0 ^ d_1 (= e ^ e2, 0 unless a fault hit one of them)
//
// v5 (serial core): the I/O buffer and the seed registers are 16-bit word
// memories (buffer word {lane, k}, seed word {entry, lane, k}, word k = lane
// bits [16k+15:16k]); every operation moves one word at a time. Compress_d is
// a d-step restoring division (no multiplier), Decompress_d accumulates
// q * bit per decoded bit, and the replay-window arithmetic runs on 16-bit
// words with a borrow.
//
// Instruction fields: see pqse_defs.vh / pqse_ucode.v (u_io).
// -----------------------------------------------------------------------------
module pqse_io (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [95:0] ins,
  output wire        busy,
  output reg         bad_set,
  output reg         fault_set,   // IO_SEQ: the two masked values differ
  // polynomial RAM
  output reg         re,
  output reg  [10:0] raddr,
  input  wire [23:0] rdata,
  output reg         we,
  output reg  [10:0] waddr,
  output reg  [23:0] wdata,
  // I/O buffer (16-bit words, address {lane, k})
  output reg         bre,
  output reg  [10:0] braddr,
  input  wire [15:0] brdata,
  output reg         bwe,
  output reg  [10:0] bwaddr,
  output reg  [15:0] bwdata,
  // seed registers (16-bit words, address {entry, lane, k})
  output reg         sre,
  output reg  [7:0]  sraddr,
  input  wire [15:0] srd0,
  input  wire [15:0] srd1,
  output reg         swe,
  output reg  [7:0]  swaddr,
  output reg  [15:0] swd0,
  output reg  [15:0] swd1,
  // randomness
  input  wire [63:0] rnd,
  output reg         rnd_take,
  // raw TRNG words (IO_T2B, TEST only: entropy assessment)
  output wire        t_en,
  input  wire        t_valid,
  input  wire [63:0] t_word,
  output wire        t_take,
  // secure-messaging counters (pqse_core.v)
  input  wire [63:0] ctr_tx,     // next send counter                      (IO_CTRW)
  input  wire        rx_any,     // a message was accepted with this key   (IO_CTRC)
  input  wire [63:0] rx_max,     // the highest accepted counter
  input  wire [63:0] rx_bits,    // bit k: counter rx_max - k was accepted
  output reg  [63:0] ctr_rx,     // the counter read by IO_CTRC
  output reg         rx_new,     // ... is newer than rx_max
  output reg  [6:0]  rx_dist     // ... by (rx_new) / older by (!rx_new); 64 = 64 or more
);
  `include "pqse_defs.vh"
  `include "pqse_func.vh"

  localparam [12:0] Q13 = 13'd3329;

  // the sequencer's instruction register holds still until this unit is idle
  // again (v5: no 96-bit copy)
  wire [95:0] J      = ins;
  wire [3:0]  j_op   = J[91:88];
  wire [1:0]  j_dm   = J[87:86];
  wire [3:0]  j_d    = J[85:82];
  wire        j_cmp  = J[81];
  wire        j_mchk = J[80];
  wire [8:0]  j_ba   = J[79:71];
  wire [3:0]  j_sl   = J[70:67];
  wire [3:0]  j_e    = J[66:63];
  wire [3:0]  j_e2   = J[62:59];

  reg         busy_r;
  assign busy = start | busy_r;

  // x + y (sb = 0) or x - y (sb = 1) mod q: one adder / subtractor and one correction
  function [11:0] asq(input [11:0] x, input [11:0] y, input sb);
    reg [12:0] s, t;
    begin
      s   = sb ? ({1'b0, x} - {1'b0, y}) : ({1'b0, x} + {1'b0, y});
      t   = sb ? (s + 13'd3329) : (s - 13'd3329);
      asq = sb ? (s[12] ? t[11:0] : s[11:0]) : ((s >= 13'd3329) ? t[11:0] : s[11:0]);
    end
  endfunction

  function [15:0] w16(input [63:0] v, input [1:0] k);    // word k of a lane
    case (k)
      2'd0:    w16 = v[15:0];
      2'd1:    w16 = v[31:16];
      2'd2:    w16 = v[47:32];
      default: w16 = v[63:48];
    endcase
  endfunction

  // ---- word counter of the seed / buffer ops: wi = {lane, k} -------------------------------
  reg  [3:0]  wi;
  wire [1:0]  li = wi[3:2];
  wire [1:0]  wk = wi[1:0];

  // ---- T2B: 136 raw TRNG words into buffer lanes ba .. ba+135, 4 words each ----
  reg  [7:0]  tl;
  wire        t2b = (j_op == IO_T2B);
  assign t_en   = busy_r && t2b;
  assign t_take = busy_r && t2b && t_valid && (wk == 2'd3);

  // ---- DEC / ENC: bit-serial (one bit per clock) -------------------------------------------
  // DEC: a buffer word is loaded into L and shifted out LSB first; bit cb of
  // the coefficient goes to cy[cb], d bits make a coefficient. Decompress_d
  // runs alongside: ar <= (ar + bit * q) / 2 per bit (rb = the bit shifted
  // out), so after d bits ar + rb = round(q y / 2^d).
  // ENC: Compress_d is a d-step restoring division of x 2^d by q (quotient
  // bits into cy, remainder in ar), rounded up when the remainder is > q/2:
  // the +1 rides on the LSB-first output as a serial carry (ec). The
  // coefficient's d bits are shifted out of cy into the top of L; 16 bits
  // make a word. A polynomial is 256 d bits = 16 d words.
  reg  [15:0]  L;         // DEC: word being consumed / ENC: word being filled
  reg  [4:0]   lb;        // DEC: bits left in L / ENC: bits in L
  reg  [11:0]  cy;        // DEC: bits collected / ENC: bits to emit (LSB first)
  reg  [3:0]   cb;        // DEC: bits collected / ENC: bits left to emit
  reg  [12:0]  ar;        // DEC: Decompress accumulator / ENC: division remainder
  reg          rb;        // DEC: rounding bit
  reg          ec;        // ENC: rounding carry
  reg  [3:0]   dc;        // ENC: division steps left
  reg          pend;      // a word read is in flight
  reg  [10:0]  la;        // buffer word address of every operation: starts at lane ba, counts up
  reg  [8:0]   ci;        // coefficient index 0..256
  reg  [11:0]  v0q, v1q;
  reg          wpend;
  reg  [6:0]   wpw;       // word to write

  wire        dec   = (j_op == IO_DEC);
  wire        dneed = busy_r && dec && (ci < 9'd256) && (cb != j_d);   // more bits needed
  wire        ext   = busy_r && dec && (ci < 9'd256) && (cb == j_d);   // a coefficient is complete
  wire        rd_word = dneed && (lb == 5'd0) && !pend;
  wire        dbit  = L[0];
  wire [12:0] dsum  = ar + (dbit ? Q13 : 13'd0);
  wire [11:0] y     = cy;                              // bits >= d are 0
  wire        ybig  = (j_d == 4'd12) && (y >= 12'd3329);
  wire [11:0] yred  = ybig ? (y - 12'd3329) : y;
  wire [11:0] val   = j_cmp ? (ar[11:0] + {11'd0, rb}) : yred;
  wire [23:0] nw    = {v1q, v0q};
  // ADD: slot + value, RSUB: value - slot; one add-or-subtract unit per coefficient
  wire        d_sb  = (j_dm == DM_RSUB);
  wire [23:0] d_x   = d_sb ? nw : rdata;
  wire [23:0] d_y   = d_sb ? rdata : nw;
  wire [23:0] dres  = ((j_dm == DM_ADD) || d_sb) ? {asq(d_x[23:12], d_y[23:12], d_sb),
                                                    asq(d_x[11:0],  d_y[11:0],  d_sb)} : nw;
  wire        dec_done = (ci == 9'd256) && !wpend;

  localparam [2:0] E_RD = 3'd0, E_LD = 3'd1, E_CV = 3'd2, E_SH = 3'd3, E_FIN = 3'd4, E_DV = 3'd5;
  reg  [2:0]   es;
  reg  [6:0]   ew;        // word index 0..127
  reg          eph;       // coefficient of the word
  reg  [23:0]  wq;
  wire        enc   = (j_op == IO_ENC);
  wire [11:0] ex    = eph ? wq[23:12] : wq[11:0];
  wire [12:0] r2    = {ar[11:0], 1'b0};
  wire        dge   = (r2 >= Q13);
  wire        ebit  = cy[0] ^ ec;
  wire        efull = (lb == 5'd16);

  // ---- seed ops --------------------------------------------------------------------------
  reg  [1:0]  sph;        // phase (0, 1; S2B and SCMP 0, 1, 2)
  // S2B / SCMP: only lanes 0..d-1 are written / compared (d = 0: all 4)
  wire        lane_on = (j_d == 4'd0) || ({2'b00, li} < j_d);
  // S2B / SCMP unmask a word: its two shares are first copied into um0 / um1,
  // registers that only these two operations load, and combined there. The
  // seed RAM outputs (both shares of whatever word any engine reads) never
  // reach an XOR gate together.
  wire        unm     = (j_op == IO_S2B) || (j_op == IO_SCMP);
  wire        ph_end  = (j_op == IO_SZERO) || (unm ? (sph == 2'd2) : (sph == 2'd1));
  reg  [15:0] um0, um1;

  // ---- CTRC: 64-message replay window, word-serial -----------------------------------------
  // per word k of the header counter c (lane 0): a = rx_max - c, 16 bits at a
  // time with the borrow. c is newer when a borrows out of word 3; then c is
  // newer by n = 2^64 - a, which is below 64 exactly when a[63:6] is all ones
  // and a[5:0] != 0 (n = -a[5:0] mod 64). Older: by a, below 64 when a[63:6] = 0.
  wire        ctrc    = (j_op == IO_CTRC);
  reg         ab;               // borrow
  reg  [5:0]  alo;              // a[5:0]
  reg         ahi, aone;        // a[63:6] != 0, a[63:6] all ones
  wire [15:0] mw      = w16(rx_max, wk);
  wire [16:0] ad      = {1'b0, mw} - {1'b0, brdata} - {16'd0, ab};
  wire        ahi_n   = ahi  | ((wk == 2'd0) ? (|ad[15:6]) : (|ad[15:0]));
  wire        aone_n  = aone & ((wk == 2'd0) ? (&ad[15:6]) : (&ad[15:0]));
  wire [5:0]  alo_n   = (wk == 2'd0) ? ad[5:0] : alo;
  wire        newer   = ad[16];                          // word 3: c > rx_max
  wire        fresh   = !rx_any || newer || (!ahi_n && !rx_bits[alo_n]);

  // ---- TRUNC: zero the message bytes from L on -------------------------------------------------
  // tq 0..3 read header lane 1 (the length) words 0..3, checked one clock later
  // (1..4); then tq = 5 + 2m reads, 6 + 2m writes message word m (0..63)
  reg  [7:0]  tq;
  reg  [7:0]  mlen;       // L
  wire        trunc   = (j_op == IO_TRUNC);
  wire [7:0]  tu      = tq - 8'd5;
  wire [5:0]  tm      = tu[6:1];                           // message word
  wire        tchk    = (tq >= 8'd1) && (tq <= 8'd4);
  wire        tbad    = (tq == 8'd1) ? ((brdata == 16'd0) || (brdata > 16'd128)) : (brdata != 16'd0);
  wire [15:0] tmask   = {({1'b0, tm, 1'b1} < mlen) ? 8'hFF : 8'h00,
                         ({1'b0, tm, 1'b0} < mlen) ? 8'hFF : 8'h00};

  // ---- SEQ: share-wise comparison of two masked seed entries --------------------------------
  // even sq <= 30: read e word sq/2; odd sq <= 31: read e2 word (sq-1)/2 (e word
  // captured); the share-wise differences are registered at the next even sq
  // and checked at the odd one after (the last at sq = 33)
  reg  [5:0]  sq;
  reg  [15:0] sa0, sa1;   // entry e word, share 0 / share 1
  reg  [15:0] sd0, sd1;   // e ^ e2 per share (registered: the shares never meet unregistered)
  wire        seq     = (j_op == IO_SEQ);

  // ---- combinational outputs -------------------------------------------------------------------
  always @* begin
    re = 1'b0; raddr = 11'd0; we = 1'b0; waddr = 11'd0; wdata = 24'd0;
    bre = 1'b0; braddr = 11'd0; bwe = 1'b0; bwaddr = 11'd0; bwdata = 16'd0;
    sre = 1'b0; sraddr = 8'd0; swe = 1'b0; swaddr = 8'd0; swd0 = 16'd0; swd1 = 16'd0;
    rnd_take  = 1'b0;
    bad_set   = 1'b0;
    fault_set = 1'b0;
    if (busy_r) begin
      if (seq) begin
        if (sq <= 6'd31) begin sre = 1'b1; sraddr = {sq[0] ? j_e2 : j_e, sq[4:1]}; end
        if ((sq[0] && sq >= 6'd3) || sq == 6'd33)
          if ((sd0 ^ sd1) != 16'd0) fault_set = 1'b1;
      end else if (trunc) begin
        if (tq <= 8'd3) begin bre = 1'b1; braddr = {B_SM_HDR + 9'd1, tq[1:0]}; end
        if (tchk && tbad) bad_set = 1'b1;
        if (tq >= 8'd5 && !tu[0]) begin bre = 1'b1; braddr = la; end          // message word tm
        if (tq >= 8'd6 && tu[0]) begin
          bwe = 1'b1; bwaddr = la; bwdata = brdata & tmask;
        end
      end else if (dec) begin
        if (rd_word) begin bre = 1'b1; braddr = la; end
        if (ext && !ci[0] && (j_dm == DM_ADD || j_dm == DM_RSUB)) begin
          re = 1'b1; raddr = {j_sl, ci[7:1]};
        end
        if (wpend && j_dm != DM_CHK) begin
          we = 1'b1; waddr = {j_sl, wpw}; wdata = dres;
        end
        if (ext && j_mchk && ybig) bad_set = 1'b1;
      end else if (enc) begin
        if (es == E_RD) begin re = 1'b1; raddr = {j_sl, ew}; end
        if (efull && (es == E_SH || es == E_FIN)) begin bwe = 1'b1; bwaddr = la; bwdata = L; end
      end else if (t2b) begin
        if (t_valid) begin bwe = 1'b1; bwaddr = la; bwdata = w16(t_word, wk); end
      end else if (ctrc) begin
        // header lane 0, word wk: read (sph 0), then the borrow step (sph 1)
        if (!sph) begin bre = 1'b1; braddr = la; end
        else if (wk == 2'd3 && !fresh) bad_set = 1'b1;
      end else begin
        case (j_op)
          IO_S2B: if (sph == 2'd0) begin
                    if (lane_on) begin sre = 1'b1; sraddr = {j_e, wi}; end
                  end else if (sph == 2'd2 && lane_on) begin
                    bwe = 1'b1; bwaddr = la; bwdata = um0 ^ um1;
                  end
          IO_B2S: if (!sph) begin bre = 1'b1; braddr = la; end
                  else begin swe = 1'b1; swaddr = {j_e, wi}; swd0 = brdata; swd1 = 16'd0; end
          IO_S2S: if (!sph) begin sre = 1'b1; sraddr = {j_e, wi}; end
                  else begin swe = 1'b1; swaddr = {j_e2, wi}; swd0 = srd0; swd1 = srd1; end
          IO_SZERO: begin swe = 1'b1; swaddr = {j_e, wi}; end
          IO_SREMASK: if (!sph) begin sre = 1'b1; sraddr = {j_e, wi}; end
                  else begin
                    swe = 1'b1; swaddr = {j_e, wi};
                    swd0 = srd0 ^ rnd[15:0]; swd1 = srd1 ^ rnd[15:0]; rnd_take = 1'b1;
                  end
          IO_SCMP: if (sph == 2'd0) begin
                    if (lane_on) begin sre = 1'b1; sraddr = {j_e, wi}; end
                  end else if (sph == 2'd1) begin
                    if (lane_on) begin bre = 1'b1; braddr = la; end
                  end else if (lane_on && ((um0 ^ um1) != brdata)) bad_set = 1'b1;
          // message header: lane 0 = send counter, lane 1 = length (kept), lanes 2, 3 = 0
          IO_CTRW: if (sph && li != 2'd1) begin
                    bwe = 1'b1; bwaddr = la;
                    bwdata = (li == 2'd0) ? w16(ctr_tx, wk) : 16'd0;
                  end
          default: ;
        endcase
      end
    end
  end

  // ---- sequential ----------------------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      busy_r <= 1'b0;
    end else if (start) begin
      busy_r <= 1'b1;
      L      <= 16'd0;
      lb     <= 5'd0;
      cy     <= 12'd0;
      cb     <= 4'd0;
      ar     <= 13'd0;
      rb     <= 1'b0;
      ec     <= 1'b0;
      dc     <= 4'd0;
      pend   <= 1'b0;
      la     <= {ins[79:71], 2'b00};
      ci     <= 9'd0;
      wpend  <= 1'b0;
      es     <= E_RD;
      ew     <= 7'd0;
      eph    <= 1'b0;
      wi     <= 4'd0;
      sph    <= 2'd0;
      tl     <= 8'd0;
      tq     <= 8'd0;
      sq     <= 6'd0;
      ab     <= 1'b0;
      ahi    <= 1'b0;
      aone   <= 1'b1;
    end else if (busy_r) begin
      if (seq) begin
        if (sq[0] && sq <= 6'd31) begin sa0 <= srd0; sa1 <= srd1; end          // e word
        if (!sq[0] && sq >= 6'd2) begin sd0 <= sa0 ^ srd0; sd1 <= sa1 ^ srd1; end // ^ e2 word
        sq <= sq + 6'd1;
        if (sq == 6'd33) busy_r <= 1'b0;
      end else if (trunc) begin
        if (tq == 8'd1) mlen <= brdata[7:0];
        // bad length, or cmp = 1: check only (OPEN, before the tag is checked)
        if ((tchk && tbad) || (tq == 8'd4 && j_cmp)) busy_r <= 1'b0;
        tq <= tq + 8'd1;
        if (tq >= 8'd6 && tu[0]) la <= la + 11'd1;          // message word written
        if (tq == 8'd132) busy_r <= 1'b0;
      end else if (dec) begin
        // one bit per clock from L into cy; a new word when L is empty
        pend <= rd_word;
        if (rd_word) la <= la + 11'd1;
        if (pend) begin
          L  <= brdata;
          lb <= 5'd16;
        end else if (dneed && lb != 5'd0) begin
          cy <= cy | ({11'd0, dbit} << cb);
          ar <= {1'b0, dsum[12:1]};
          rb <= dsum[0];
          L  <= {1'b0, L[15:1]};
          lb <= lb - 5'd1;
          cb <= cb + 4'd1;
        end
        if (ext) begin
          cb <= 4'd0;
          cy <= 12'd0;
          ar <= 13'd0;
          rb <= 1'b0;
          ci <= ci + 9'd1;
          if (!ci[0]) v0q <= val;
          else begin
            v1q   <= val;
            wpw   <= ci[7:1];
          end
        end
        wpend <= ext && ci[0];
        if (dec_done) busy_r <= 1'b0;
      end else if (enc) begin
        case (es)
          E_RD: es <= E_LD;                                  // word ew read
          E_LD: begin wq <= rdata; eph <= 1'b0; es <= E_CV; end
          E_CV: begin                                        // coefficient eph
            ar <= {1'b0, ex};
            cy <= j_cmp ? 12'd0 : ex;
            dc <= j_cmp ? j_d : 4'd0;
            es <= E_DV;
          end
          E_DV: begin                                        // Compress_d: d division steps
            if (dc != 4'd0) begin
              ar <= dge ? (r2 - Q13) : r2;
              cy <= {cy[10:0], dge};
              dc <= dc - 4'd1;
            end else begin
              ec <= j_cmp && (ar >= 13'd1665);               // round half up (q is odd)
              cb <= j_d;
              es <= E_SH;
            end
          end
          E_SH: begin
            if (efull) begin                                 // word L written this clock
              la <= la + 11'd1;
              lb <= 5'd0;
            end else if (cb != 4'd0) begin                   // one bit into the top of L
              L  <= {ebit, L[15:1]};
              ec <= cy[0] & ec;
              cy <= {1'b0, cy[11:1]};
              cb <= cb - 4'd1;
              lb <= lb + 5'd1;
            end else if (!eph) begin
              eph <= 1'b1;
              es  <= E_CV;
            end else if (ew != 7'd127) begin
              ew <= ew + 7'd1;
              es <= E_RD;
            end else begin
              es <= E_FIN;
            end
          end
          default: begin                                     // E_FIN: the last word is out
            if (efull) begin la <= la + 11'd1; lb <= 5'd0; end
            else busy_r <= 1'b0;
          end
        endcase
      end else if (t2b) begin
        if (t_valid) begin
          wi <= wi + 4'd1;                                   // (wk: word of the TRNG word)
          la <= la + 11'd1;
          if (wk == 2'd3) begin
            tl <= tl + 8'd1;
            if (tl == 8'd135) busy_r <= 1'b0;
          end
        end
      end else if (ctrc) begin
        if (!sph) begin
          sph <= 2'd1;
        end else begin
          ctr_rx <= {brdata, ctr_rx[63:16]};
          ab   <= ad[16];
          alo  <= alo_n;
          ahi  <= ahi_n;
          aone <= aone_n;
          sph <= 2'd0;
          wi  <= wi + 4'd1;
          la  <= la + 11'd1;
          if (wk == 2'd3) begin
            busy_r  <= 1'b0;
            rx_new  <= newer;
            rx_dist <= newer ? ((aone_n && alo_n != 6'd0) ? {1'b0, 6'd0 - alo_n} : 7'd64)
                             : (ahi_n ? 7'd64 : {1'b0, alo_n});
          end
        end
      end else begin
        if (unm && sph == 2'd1 && lane_on) begin um0 <= srd0; um1 <= srd1; end
        if (ph_end) begin
          wi  <= wi + 4'd1;
          la  <= la + 11'd1;
          sph <= 2'd0;
          if (wi == 4'd15) busy_r <= 1'b0;
        end else begin
          sph <= sph + 2'd1;
        end
      end
    end
  end
endmodule
