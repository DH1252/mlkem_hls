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
//           the 64-message replay window                                 (OPEN)
//   TRUNC   message length L = header lane 1: BAD unless 1 <= L <= 128;
//           else the bytes from L on of the 16 message lanes := 0  (SEAL, OPEN);
//           cmp = 1: the length check only, nothing is written
//   SEQ     FAULT := the masked values in seed entries e and e2 differ, found
//           without unmasking either: d_s = e_s ^ e2_s per share, registered,
//           then d_0 ^ d_1 (= e ^ e2, 0 unless a fault hit one of them)
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
  // I/O buffer
  output reg         bre,
  output reg  [8:0]  braddr,
  input  wire [63:0] brdata,
  output reg         bwe,
  output reg  [8:0]  bwaddr,
  output reg  [63:0] bwdata,
  // seed registers
  output reg         sre,
  output reg  [5:0]  sraddr,
  input  wire [63:0] srd0,
  input  wire [63:0] srd1,
  output reg         swe,
  output reg  [5:0]  swaddr,
  output reg  [63:0] swd0,
  output reg  [63:0] swd1,
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
  output reg  [63:0] ctr_rx      // the counter read by IO_CTRC
);
  `include "pqse_defs.vh"
  `include "pqse_func.vh"

  reg  [95:0] J;
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

  // ---- T2B: 136 raw TRNG words into buffer lanes ba .. ba+135 ----
  reg  [7:0]  tl;
  wire        t2b = (j_op == IO_T2B);
  assign t_en   = busy_r && t2b;
  assign t_take = busy_r && t2b && t_valid;

  // ---- compress / decompress ------------------------------------------------------
  // Compress_d(x) = round(2^d x / q) mod 2^d, exact formula as in hw/manual
  function [11:0] compress(input [11:0] x, input [3:0] d);
    reg [21:0] t;
    reg [44:0] m;
    reg [11:0] r;
    begin
      t = ({10'd0, x} << d) + 22'd1664;
      m = t * 45'd2580335;
      r = m[44:33];
      compress = r & ((12'd1 << d) - 12'd1);
    end
  endfunction
  // Decompress_d(y) = round(q y / 2^d)
  function [11:0] decompress(input [11:0] y, input [3:0] d);
    reg [23:0] t;
    begin
      t = y * 24'd3329 + (24'd1 << (d - 4'd1));
      decompress = t >> d;
    end
  endfunction

  // ---- DEC / ENC: bit-serial (one bit per clock; v4 trades clocks for area) -----------------
  // DEC: a buffer lane is loaded into L and shifted out LSB first, d bits make
  // a coefficient (collected at the top of cy). ENC: a coefficient's d bits are
  // shifted out of cy into the top of L; 64 bits make a lane. No wide barrel
  // shifters: a polynomial is 256 d bits = 4d lanes, ~13 clocks per coefficient.
  reg  [63:0]  L;         // DEC: lane being consumed / ENC: lane being filled
  reg  [6:0]   lb;        // DEC: bits left in L / ENC: bits in L
  reg  [11:0]  cy;        // DEC: bits collected (at the top) / ENC: bits to emit (LSB first)
  reg  [3:0]   cb;        // DEC: bits collected / ENC: bits left to emit
  reg          pend;      // a lane read is in flight
  reg  [8:0]   la;        // next lane to read / write
  reg  [8:0]   ci;        // coefficient index 0..256
  reg  [11:0]  v0q, v1q;
  reg          wpend;
  reg  [6:0]   wpw;       // word to write

  wire        dec   = (j_op == IO_DEC);
  wire        dneed = busy_r && dec && (ci < 9'd256) && (cb != j_d);   // more bits needed
  wire        ext   = busy_r && dec && (ci < 9'd256) && (cb == j_d);   // a coefficient is complete
  wire        rd_lane = dneed && (lb == 7'd0) && !pend;
  wire [11:0] ymask = (12'd1 << j_d) - 12'd1;
  wire [11:0] y     = (cy >> (4'd12 - j_d)) & ymask;
  wire        ybig  = (j_d == 4'd12) && (y >= 12'd3329);
  wire [11:0] yred  = ybig ? (y - 12'd3329) : y;
  wire [11:0] val   = j_cmp ? decompress(y, j_d) : yred;
  wire [23:0] nw    = {v1q, v0q};
  wire [23:0] dres  = (j_dm == DM_ADD)  ? {addq(rdata[23:12], v1q), addq(rdata[11:0], v0q)} :
                      (j_dm == DM_RSUB) ? {subq(v1q, rdata[23:12]), subq(v0q, rdata[11:0])} : nw;
  wire        dec_done = (ci == 9'd256) && !wpend;

  localparam [2:0] E_RD = 3'd0, E_LD = 3'd1, E_CV = 3'd2, E_SH = 3'd3, E_FIN = 3'd4;
  reg  [2:0]   es;
  reg  [6:0]   ew;        // word index 0..127
  reg          eph;       // coefficient of the word
  reg  [23:0]  wq;
  wire        enc   = (j_op == IO_ENC);
  wire [11:0] ex    = eph ? wq[23:12] : wq[11:0];
  wire [11:0] cv    = j_cmp ? compress(ex, j_d) : ex;
  wire        efull = (lb == 7'd64);

  // ---- seed ops --------------------------------------------------------------------------
  reg  [1:0]  li;         // lane 0..3
  reg  [1:0]  sph;        // phase (0, 1; S2B and SCMP 0, 1, 2)
  // S2B / SCMP: only lanes 0..d-1 are written / compared (d = 0: all 4)
  wire        lane_on = (j_d == 4'd0) || ({2'b00, li} < j_d);
  // S2B / SCMP unmask a lane: its two shares are first copied into um0 / um1,
  // registers that only these two operations load, and combined there. The
  // seed RAM outputs (both shares of whatever lane any engine reads) never
  // reach an XOR gate together.
  wire        unm     = (j_op == IO_S2B) || (j_op == IO_SCMP);
  wire        ph_end  = (j_op == IO_SZERO) || (unm ? (sph == 2'd2) : (sph == 2'd1));
  reg  [63:0] um0, um1;

  // ---- CTRC: 64-message replay window ------------------------------------------------------
  wire [63:0] age     = rx_max - brdata;                 // how far behind the newest accepted
  wire        fresh   = !rx_any || (brdata > rx_max) ||
                        ((age < 64'd64) && !rx_bits[age[5:0]]);

  // ---- TRUNC: zero the message bytes from L on -------------------------------------------------
  reg  [5:0]  tq;         // 0 read header lane 1, 1 check, 2..33 read / write the 16 lanes
  reg  [7:0]  mlen;       // L
  wire        trunc   = (j_op == IO_TRUNC);
  wire [3:0]  tk      = tq[4:1] - 4'd1;                  // lane (2 + 2k: read, 3 + 2k: write)
  reg  [63:0] tmask;
  integer     tb_;
  always @* begin
    for (tb_ = 0; tb_ < 8; tb_ = tb_ + 1)
      tmask[8*tb_ +: 8] = (({1'b0, tk, 3'b000} + tb_) < {1'b0, mlen}) ? 8'hFF : 8'h00;
  end

  // ---- SEQ: share-wise comparison of two masked seed entries --------------------------------
  reg  [3:0]  sq;         // 0..9 (see below)
  reg  [63:0] sa0, sa1;   // entry e lane, share 0 / share 1
  reg  [63:0] sd0, sd1;   // e ^ e2 per share (registered: the shares never meet unregistered)
  wire        seq     = (j_op == IO_SEQ);

  // ---- combinational outputs -------------------------------------------------------------------
  always @* begin
    re = 1'b0; raddr = 11'd0; we = 1'b0; waddr = 11'd0; wdata = 24'd0;
    bre = 1'b0; braddr = 9'd0; bwe = 1'b0; bwaddr = 9'd0; bwdata = 64'd0;
    sre = 1'b0; sraddr = 6'd0; swe = 1'b0; swaddr = 6'd0; swd0 = 64'd0; swd1 = 64'd0;
    rnd_take  = 1'b0;
    bad_set   = 1'b0;
    fault_set = 1'b0;
    if (busy_r) begin
      if (seq) begin
        // even sq < 8: read e lane sq/2; odd sq: read e2 lane (sq-1)/2 (e lane captured);
        // the share-wise differences are registered one clock later and checked the next
        if (sq <= 4'd7) begin sre = 1'b1; sraddr = {sq[0] ? j_e2 : j_e, sq[2:1]}; end
        if ((sq[0] && sq >= 4'd3) || sq == 4'd9)
          if ((sd0 ^ sd1) != 64'd0) fault_set = 1'b1;
      end else if (trunc) begin
        if (tq == 6'd0) begin bre = 1'b1; braddr = B_SM_HDR + 9'd1; end
        if (tq == 6'd1 && (brdata == 64'd0 || brdata > 64'd128)) bad_set = 1'b1;
        if (tq >= 6'd2 && !tq[0]) begin bre = 1'b1; braddr = j_ba + {5'd0, tk}; end
        if (tq >= 6'd3 && tq[0]) begin
          bwe = 1'b1; bwaddr = j_ba + {5'd0, tk}; bwdata = brdata & tmask;
        end
      end else if (dec) begin
        if (rd_lane) begin bre = 1'b1; braddr = la; end
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
        if (t_valid) begin bwe = 1'b1; bwaddr = j_ba + {1'b0, tl}; bwdata = t_word; end
      end else begin
        case (j_op)
          IO_S2B: if (sph == 2'd0) begin
                    if (lane_on) begin sre = 1'b1; sraddr = {j_e, li}; end
                  end else if (sph == 2'd2 && lane_on) begin
                    bwe = 1'b1; bwaddr = j_ba + {7'd0, li}; bwdata = um0 ^ um1;
                  end
          IO_B2S: if (!sph) begin bre = 1'b1; braddr = j_ba + {7'd0, li}; end
                  else begin swe = 1'b1; swaddr = {j_e, li}; swd0 = brdata; swd1 = 64'd0; end
          IO_S2S: if (!sph) begin sre = 1'b1; sraddr = {j_e, li}; end
                  else begin swe = 1'b1; swaddr = {j_e2, li}; swd0 = srd0; swd1 = srd1; end
          IO_SZERO: begin swe = 1'b1; swaddr = {j_e, li}; end
          IO_SREMASK: if (!sph) begin sre = 1'b1; sraddr = {j_e, li}; end
                  else begin
                    swe = 1'b1; swaddr = {j_e, li};
                    swd0 = srd0 ^ rnd; swd1 = srd1 ^ rnd; rnd_take = 1'b1;
                  end
          IO_SCMP: if (sph == 2'd0) begin
                    if (lane_on) begin sre = 1'b1; sraddr = {j_e, li}; end
                  end else if (sph == 2'd1) begin
                    if (lane_on) begin bre = 1'b1; braddr = j_ba + {7'd0, li}; end
                  end else if (lane_on && ((um0 ^ um1) != brdata)) bad_set = 1'b1;
          // message header: lane 0 = send counter, lane 1 = length (kept), lanes 2, 3 = 0
          IO_CTRW: if (sph && li != 2'd1) begin
                    bwe = 1'b1; bwaddr = j_ba + {7'd0, li};
                    bwdata = (li == 2'd0) ? ctr_tx : 64'd0;
                  end
          // replay check against the 64-message window
          IO_CTRC: if (!sph) begin
                    bre = 1'b1; braddr = j_ba + {7'd0, li};
                  end else if (li == 2'd0 && !fresh) bad_set = 1'b1;
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
      J      <= ins;
      busy_r <= 1'b1;
      L      <= 64'd0;
      lb     <= 7'd0;
      cy     <= 12'd0;
      cb     <= 4'd0;
      pend   <= 1'b0;
      la     <= ins[79:71];
      ci     <= 9'd0;
      wpend  <= 1'b0;
      es     <= E_RD;
      ew     <= 7'd0;
      eph    <= 1'b0;
      li     <= 2'd0;
      sph    <= 2'd0;
      tl     <= 8'd0;
      tq     <= 6'd0;
      sq     <= 4'd0;
    end else if (busy_r) begin
      if (seq) begin
        if (sq[0] && sq <= 4'd7) begin sa0 <= srd0; sa1 <= srd1; end          // e lane
        if (!sq[0] && sq >= 4'd2) begin sd0 <= sa0 ^ srd0; sd1 <= sa1 ^ srd1; end // ^ e2 lane
        sq <= sq + 4'd1;
        if (sq == 4'd9) busy_r <= 1'b0;
      end else if (trunc) begin
        if (tq == 6'd1) begin
          mlen <= brdata[7:0];
          // bad length, or cmp = 1: check only (OPEN, before the tag is checked)
          if (brdata == 64'd0 || brdata > 64'd128 || j_cmp) busy_r <= 1'b0;
        end
        tq <= tq + 6'd1;
        if (tq == 6'd33) busy_r <= 1'b0;
      end else if (dec) begin
        // one bit per clock from L into cy; a new lane when L is empty
        pend <= rd_lane;
        if (rd_lane) la <= la + 9'd1;
        if (pend) begin
          L  <= brdata;
          lb <= 7'd64;
        end else if (dneed && lb != 7'd0) begin
          cy <= {L[0], cy[11:1]};
          L  <= {1'b0, L[63:1]};
          lb <= lb - 7'd1;
          cb <= cb + 4'd1;
        end
        if (ext) begin
          cb <= 4'd0;
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
          E_CV: begin cy <= cv; cb <= j_d; es <= E_SH; end    // coefficient eph, d bits
          E_SH: begin
            if (efull) begin                                 // lane L written this clock
              la <= la + 9'd1;
              lb <= 7'd0;
            end else if (cb != 4'd0) begin                   // one bit into the top of L
              L  <= {cy[0], L[63:1]};
              cy <= {1'b0, cy[11:1]};
              cb <= cb - 4'd1;
              lb <= lb + 7'd1;
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
          default: begin                                     // E_FIN: the last lane is out
            if (efull) begin la <= la + 9'd1; lb <= 7'd0; end
            else busy_r <= 1'b0;
          end
        endcase
      end else if (t2b) begin
        if (t_valid) begin
          tl <= tl + 8'd1;
          if (tl == 8'd135) busy_r <= 1'b0;
        end
      end else begin
        if (unm && sph == 2'd1 && lane_on) begin um0 <= srd0; um1 <= srd1; end
        if (j_op == IO_CTRC && sph == 2'd1 && li == 2'd0) ctr_rx <= brdata;
        if (ph_end) begin
          li  <= li + 2'd1;
          sph <= 2'd0;
          if (li == 2'd3) busy_r <= 1'b0;
        end else begin
          sph <= sph + 2'd1;
        end
      end
    end
  end
endmodule
