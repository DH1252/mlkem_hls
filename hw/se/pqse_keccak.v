// -----------------------------------------------------------------------------
// pqse_keccak.v - first-order masked, lane-serial Keccak-f[1600], state in RAM.
//
// Compact / low-power version (v4): the state lives in two small RAMs, one per
// Boolean share (A0 ^ A1 = state), 64 words x 64 bits each, instead of 3,200
// flip-flops behind 25-way lane multiplexers. Per share:
//     words  0..24  the state lanes A[x + 5y]
//     words 25..29  the column parities C[x] (theta)
//     words 32..56  B = pi(rho(theta(A))), lane B[y + 5((2x + 3y) mod 5)]
// One read and one write per clock (simple dual-port RAM, registered read:
// an FPGA block RAM, a small SRAM macro or latch register file on a chip).
// Both shares run in lockstep through the same addresses, each with its own
// data path; they meet only in the registered DOM cross terms of chi.
//
// One round = three passes, 162 clocks (a permutation 3,890 clocks):
//   TH   26 clocks  C[x] = A[x] ^ A[x+5] ^ ... ^ A[x+20]          -> words 25..29
//   RP   36 clocks  per column x: D = C[x-1] ^ rol(C[x+1], 1) into T, then
//                   B[pi(x, y)] = rol(A[x + 5y] ^ D, r[x, y])          -> words 32..56
//   CHI 100 clocks  per plane y, lanes in the order 0, 2, 4, 1, 3, 4 clocks each:
//                     c0  read B[x+1]
//                     c1  X <= ~B[x+1] (NOT on share 0)      read B[x+2]
//                     c2  Y <= B[x+2]                       read B[x]
//                     c3  DOM AND -> d00 d01 d10 d11 (64 fresh random bits),
//                         X and Y cleared
//                     c0' A[x + 5y] <= B[x] ^ d00 ^ d01 (^ iota)  (share 0)
//                                      B[x] ^ d11 ^ d10           (share 1)
// DOM AND (Gross et al., "Domain-Oriented Masking", TIS 2016):
//   d00 = X0&Y0   d01 = X0&Y1 ^ r   d10 = X1&Y0 ^ r   d11 = X1&Y1   (registered)
// Robust-probing details (first order, glitches + transitions; checked by
// scripts/pqse_probe_verify.py, gadget "Keccak chi, state in RAM"):
//   - each share has its own RAM, so a RAM's output register only ever holds
//     one share; the operand registers take one lane each (X from B[x+1], Y
//     from B[x+2]) and are cleared after the AND, so the AND gate never sees
//     share 0 and share 1 of the same lane, not even in consecutive clocks
//   - the products load every clock (0 except right after the AND)
//   - the write-back has its own cone (B[x], d00, d01 / d11, d10)
// Absorb (sponge): state[i] ^= v is a read-modify-write, written the clock
// after ax_en; reads (rd_en) deliver the lane the clock after the request.
// Wipe: while clr is high and the RAMs are not known to be clean, every word
// of both RAMs is written 0 (64 clocks), then word 0 is read so the RAM output
// registers hold 0 (no key or state material left anywhere).
//
// msk = 0 (unmasked job): share 1 stays zero, its RAM is not clocked, r = 0.
// MASKED = 0: the share-1 RAM and data path are not built.
//
// UNTESTED FIRST VERSION - see hw/se/README.md.
// -----------------------------------------------------------------------------
module pqse_keccak #(
  parameter MASKED   = 1,
  parameter RAMSTYLE = 0
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        msk,        // this job is masked
  // lane access while idle
  // contract (pqse_sponge.v keeps it): ax_en / rd_en only while no permutation,
  // wipe or chi write-back runs, never together with go, and never two absorbs
  // of the same lane in consecutive clocks (back-to-back absorbs of different
  // lanes are fine: the read of one overlaps the write of the other)
  input  wire        clr,        // keep the state zero: wipe it unless already clean (busy meanwhile)
  input  wire        ax_en,      // state[ax_idx] ^= {ax_v1, ax_v0} (written the next clock)
  input  wire [4:0]  ax_idx,
  input  wire [63:0] ax_v0,
  input  wire [63:0] ax_v1,
  input  wire        rd_en,      // read lane rd_idx: on rd_v0 / rd_v1 from the next clock (held)
  input  wire [4:0]  rd_idx,
  output wire [63:0] rd_v0,
  output wire [63:0] rd_v1,
  // permutation
  input  wire        go,
  output wire        busy,
  input  wire [63:0] rnd,
  output wire        rnd_take
);
  localparam M1 = (MASKED != 0);

  // ---- constants -------------------------------------------------------------
  function [63:0] rc_of(input [4:0] r);
    case (r)
      5'd0:  rc_of = 64'h0000000000000001; 5'd1:  rc_of = 64'h0000000000008082;
      5'd2:  rc_of = 64'h800000000000808A; 5'd3:  rc_of = 64'h8000000080008000;
      5'd4:  rc_of = 64'h000000000000808B; 5'd5:  rc_of = 64'h0000000080000001;
      5'd6:  rc_of = 64'h8000000080008081; 5'd7:  rc_of = 64'h8000000000008009;
      5'd8:  rc_of = 64'h000000000000008A; 5'd9:  rc_of = 64'h0000000000000088;
      5'd10: rc_of = 64'h0000000080008009; 5'd11: rc_of = 64'h000000008000000A;
      5'd12: rc_of = 64'h000000008000808B; 5'd13: rc_of = 64'h800000000000008B;
      5'd14: rc_of = 64'h8000000000008089; 5'd15: rc_of = 64'h8000000000008003;
      5'd16: rc_of = 64'h8000000000008002; 5'd17: rc_of = 64'h8000000000000080;
      5'd18: rc_of = 64'h000000000000800A; 5'd19: rc_of = 64'h800000008000000A;
      5'd20: rc_of = 64'h8000000080008081; 5'd21: rc_of = 64'h8000000000008080;
      5'd22: rc_of = 64'h0000000080000001; default: rc_of = 64'h8000000080008008;
    endcase
  endfunction

  // rotation offset of lane i = x + 5y (FIPS 202 Table 2)
  function [5:0] rho(input [4:0] i);
    case (i)
      5'd0:  rho = 6'd0;   5'd1:  rho = 6'd1;   5'd2:  rho = 6'd62;  5'd3:  rho = 6'd28;  5'd4:  rho = 6'd27;
      5'd5:  rho = 6'd36;  5'd6:  rho = 6'd44;  5'd7:  rho = 6'd6;   5'd8:  rho = 6'd55;  5'd9:  rho = 6'd20;
      5'd10: rho = 6'd3;   5'd11: rho = 6'd10;  5'd12: rho = 6'd43;  5'd13: rho = 6'd25;  5'd14: rho = 6'd39;
      5'd15: rho = 6'd41;  5'd16: rho = 6'd45;  5'd17: rho = 6'd15;  5'd18: rho = 6'd21;  5'd19: rho = 6'd8;
      5'd20: rho = 6'd18;  5'd21: rho = 6'd2;   5'd22: rho = 6'd61;  5'd23: rho = 6'd56;  default: rho = 6'd14;
    endcase
  endfunction

  // pi: lane (x, y) = x + 5y goes to (y, 2x + 3y), index y + 5((2x + 3y) mod 5)
  function [4:0] pdst(input [4:0] i);
    case (i)
      5'd0:  pdst = 5'd0;  5'd1:  pdst = 5'd10; 5'd2:  pdst = 5'd20; 5'd3:  pdst = 5'd5;  5'd4:  pdst = 5'd15;
      5'd5:  pdst = 5'd16; 5'd6:  pdst = 5'd1;  5'd7:  pdst = 5'd11; 5'd8:  pdst = 5'd21; 5'd9:  pdst = 5'd6;
      5'd10: pdst = 5'd7;  5'd11: pdst = 5'd17; 5'd12: pdst = 5'd2;  5'd13: pdst = 5'd12; 5'd14: pdst = 5'd22;
      5'd15: pdst = 5'd23; 5'd16: pdst = 5'd8;  5'd17: pdst = 5'd18; 5'd18: pdst = 5'd3;  5'd19: pdst = 5'd13;
      5'd20: pdst = 5'd14; 5'd21: pdst = 5'd24; 5'd22: pdst = 5'd9;  5'd23: pdst = 5'd19; default: pdst = 5'd4;
    endcase
  endfunction

  // rotate left: one 6-stage barrel rotator (a shift-left | shift-right pair
  // would build two barrel shifters)
  function [63:0] rol(input [63:0] v, input [5:0] n);
    reg [63:0] t;
    begin
      t = v;
      if (n[0]) t = {t[62:0], t[63]};
      if (n[1]) t = {t[61:0], t[63:62]};
      if (n[2]) t = {t[59:0], t[63:60]};
      if (n[3]) t = {t[55:0], t[63:56]};
      if (n[4]) t = {t[47:0], t[63:48]};
      if (n[5]) t = {t[31:0], t[63:32]};
      rol = t;
    end
  endfunction

  function [2:0] m5(input [3:0] v);     // v mod 5 for v < 10
    m5 = (v >= 4'd5) ? v - 4'd5 : v[2:0];
  endfunction

  function [4:0] lidx(input [2:0] x, input [2:0] y);   // x + 5y
    lidx = {2'b00, x} + {y, 2'b00} + {2'b00, y};
  endfunction

  function [2:0] lo(input [2:0] k);     // chi lane order 0, 2, 4, 1, 3
    lo = m5({k, 1'b0});
  endfunction

  // ---- state -----------------------------------------------------------------------
  localparam [2:0] K_IDLE = 3'd0, K_WIPE = 3'd1, K_TH = 3'd2, K_RP = 3'd3, K_CHI = 3'd4;
  reg  [2:0]  ks;
  reg  [4:0]  rnd_i;      // round 0..23
  reg         mj;         // latched msk of the running permutation
  reg         clean;      // both RAMs hold only zeros
  reg  [5:0]  wcnt;       // wipe address
  // pass counters (issue stage)
  reg  [2:0]  cx, cy, cj;
  reg  [1:0]  cs;         // chi: clock within the lane slot
  reg         iss;        // TH / RP: reads left to issue
  // data stage (TH / RP: the read issued last clock)
  reg         dv;
  reg  [2:0]  dx, dy, dj;
  // per-share registers
  reg  [63:0] T0, T1;              // theta: parity accumulator / D lane
  reg  [63:0] X0r, X1r, Y0r, Y1r;  // chi: DOM operands
  reg  [63:0] d00, d01, d10, d11;  // chi: DOM partial products
  reg         wbv;                 // chi: write-back pending (this clock)
  reg  [4:0]  wbi;
  // absorb pipeline
  reg         ap;
  reg         apn;                 // apv may hold a lane value (loaded last clock)
  reg  [4:0]  apa;
  reg  [63:0] apv0, apv1;

  wire        use1 = M1 && mj;
  wire [63:0] rr   = use1 ? rnd : 64'd0;
  wire        dom_now = (ks == K_CHI) && (cs == 2'd3);
  assign rnd_take = dom_now && use1;
  assign busy = go | (ks != K_IDLE) | ap | wbv | (clr && !clean);

  // ---- RAMs: one per share ---------------------------------------------------------
  reg         re, we;
  reg  [5:0]  ra, wa;
  reg  [63:0] wd0, wd1;
  wire [63:0] q0, q1;
  // share 1 is clocked only when it can hold data: absorb / reads / wipe, or a masked
  // permutation (an unmasked one's last write-back lands in K_IDLE: not on share 1)
  wire        en1 = M1 && (mj || (ks == K_WIPE) || ((ks == K_IDLE) && !wbv));

  pqse_ram_1r1w #(.AW(6), .DW(64), .RAMSTYLE(RAMSTYLE)) u_s0 (
    .clk(clk), .we(we), .waddr(wa), .wdata(wd0), .re(re), .raddr(ra), .rdata(q0));
  generate
    if (M1) begin : g_s1
      pqse_ram_1r1w #(.AW(6), .DW(64), .RAMSTYLE(RAMSTYLE)) u_s1 (
        .clk(clk), .we(we & en1), .waddr(wa), .wdata(wd1), .re(re & en1), .raddr(ra), .rdata(q1));
    end else begin : g_n1
      assign q1 = 64'd0;
    end
  endgenerate

  assign rd_v0 = q0;
  assign rd_v1 = M1 ? q1 : 64'd0;

  // ---- data paths ----------------------------------------------------------------------
  wire [2:0]  chx  = lo(cj);                          // chi: the lane of this slot
  wire [2:0]  chx1 = m5({1'b0, chx} + 4'd1);
  wire [2:0]  chx2 = m5({1'b0, chx} + 4'd2);
  wire [4:0]  rpi  = lidx(dx, dj - 3'd2);             // RP: lane of the data stage (dj >= 2)
  wire [5:0]  rot  = rho(rpi);
  wire [63:0] th0  = T0 ^ q0;                         // TH: parity so far ^ this lane
  wire [63:0] th1  = T1 ^ q1;
  wire [63:0] rp0  = rol(q0 ^ T0, rot);               // RP: rol(A ^ D, r)
  wire [63:0] rp1  = rol(q1 ^ T1, rot);
  wire [63:0] iota = (wbv && wbi == 5'd0) ? rc_of(rnd_i) : 64'd0;
  wire        rp_w = (ks == K_RP) && dv && (dj >= 3'd2);

  always @* begin
    re = 1'b0; ra = 6'd0; we = 1'b0; wa = 6'd0;
    // ---- write data: every source is "q ^ x" with the x's 0 when unused
    // (absorb apv, chi products + iota, theta parity T), except the rho/pi
    // lane (rotated) and the wipe (0) ----
    wd0 = (ks == K_WIPE) ? 64'd0 : rp_w ? rp0 : (q0 ^ apv0 ^ d00 ^ d01 ^ iota ^ T0);
    wd1 = (ks == K_WIPE) ? 64'd0 : rp_w ? rp1 : (q1 ^ apv1 ^ d11 ^ d10 ^ T1);
    // ---- write enable / address (one source per clock) ----
    if (ap) begin                                       // absorb: lane ^ v
      we = 1'b1; wa = {1'b0, apa};
    end else if (wbv) begin                             // chi write-back
      we = 1'b1; wa = {1'b0, wbi};
    end else if (ks == K_WIPE) begin                    // zeros
      we = 1'b1; wa = wcnt;
    end else if ((ks == K_TH) && dv && (dy == 3'd4)) begin   // C[x] = T ^ A[x + 20]
      we = 1'b1; wa = 6'd25 + {3'd0, dx};
    end else if (rp_w) begin
      we = 1'b1; wa = 6'd32 + {1'b0, pdst(rpi)};
    end
    // ---- the read port ----
    case (ks)
      K_IDLE:
        if (ax_en)      begin re = 1'b1; ra = {1'b0, ax_idx}; end
        else if (rd_en) begin re = 1'b1; ra = {1'b0, rd_idx}; end
      K_WIPE:                                           // last clock: word 0 (zero by now) into
        if (wcnt == 6'd63) begin re = 1'b1; ra = 6'd0; end   // the output registers
      K_TH:
        if (iss) begin re = 1'b1; ra = {1'b0, lidx(cx, cy)}; end
      K_RP:
        if (iss) begin
          re = 1'b1;
          ra = (cj == 3'd0) ? 6'd25 + {3'd0, m5({1'b0, cx} + 4'd4)} :   // C[x-1]
               (cj == 3'd1) ? 6'd25 + {3'd0, m5({1'b0, cx} + 4'd1)} :   // C[x+1]
                              {1'b0, lidx(cx, cj - 3'd2)};              // A[x + 5y]
        end
      K_CHI:
        if (cs != 2'd3) begin
          re = 1'b1;
          ra = 6'd32 + {1'b0, lidx((cs == 2'd0) ? chx1 : (cs == 2'd1) ? chx2 : chx, cy)};
        end
      default: ;
    endcase
  end

  // ---- control and registers --------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      ks <= K_IDLE; mj <= 1'b0; clean <= 1'b0; ap <= 1'b0; wbv <= 1'b0; dv <= 1'b0; iss <= 1'b0;
      apn <= 1'b0; apv0 <= 64'd0; apv1 <= 64'd0; T0 <= 64'd0; T1 <= 64'd0;
      X0r <= 64'd0; X1r <= 64'd0; Y0r <= 64'd0; Y1r <= 64'd0;
      d00 <= 64'd0; d01 <= 64'd0; d10 <= 64'd0; d11 <= 64'd0;
    end else begin
      // absorb: the lane is written the next clock (from apv, 0 outside an absorb).
      // Low power: apa / apv load only in an absorb clock and the clock after
      // it (back to 0), then hold 0 - their clock can be gated between absorbs
      ap   <= ax_en && (ks == K_IDLE);
      apn  <= ax_en;
      if (ax_en || apn) begin
        apa  <= ax_idx;
        apv0 <= ax_en ? ax_v0 : 64'd0;
        apv1 <= (ax_en && M1) ? ax_v1 : 64'd0;
      end
      // chi: Y and the products load every clock while a permutation runs
      // (their value in their clock, else 0), up to the last write-back clock;
      // then they are 0 and hold, so an idle Keccak's clock can be gated
      // (low power: 384 flip-flops) without a hold path in use
      if ((ks != K_IDLE) || wbv) begin
        Y0r <= 64'd0; Y1r <= 64'd0;
        d00 <= 64'd0; d01 <= 64'd0; d10 <= 64'd0; d11 <= 64'd0;
        if (dom_now) begin
          d00 <= X0r & Y0r;
          d01 <= (X0r & Y1r) ^ rr;
          d10 <= (X1r & Y0r) ^ rr;
          d11 <= X1r & Y1r;
        end
      end
      wbv <= 1'b0;

      case (ks)
        K_IDLE: begin
          if (ax_en) clean <= 1'b0;
          if (go) begin
            ks    <= K_TH;
            mj    <= msk;
            rnd_i <= 5'd0;
            clean <= 1'b0;
            cx    <= 3'd0;
            cy    <= 3'd0;
            iss   <= 1'b1;
            dv    <= 1'b0;
          end else if (clr && !clean && !ax_en && !ap && !wbv) begin
            ks   <= K_WIPE;
            wcnt <= 6'd0;
          end
        end

        K_WIPE: begin
          wcnt <= wcnt + 6'd1;
          T0 <= 64'd0; T1 <= 64'd0;
          if (wcnt == 6'd63) begin
            ks    <= K_IDLE;
            clean <= 1'b1;
          end
        end

        // ---- theta, part 1: column parities ----
        K_TH: begin
          if (iss) begin
            if (cy == 3'd4) begin
              cy <= 3'd0;
              if (cx == 3'd4) iss <= 1'b0; else cx <= cx + 3'd1;
            end else begin
              cy <= cy + 3'd1;
            end
          end
          dv <= iss; dx <= cx; dy <= cy;
          if (dv) begin
            T0 <= (dy == 3'd0) ? q0 : th0;
            T1 <= (dy == 3'd0) ? q1 : th1;
            if (dx == 3'd4 && dy == 3'd4) begin          // C[4] written this clock
              ks  <= K_RP;
              cx  <= 3'd0;
              cj  <= 3'd0;
              iss <= 1'b1;
              dv  <= 1'b0;
            end
          end
        end

        // ---- theta, part 2 (D), rho and pi, one column at a time ----
        K_RP: begin
          if (iss) begin
            if (cj == 3'd6) begin
              cj <= 3'd0;
              if (cx == 3'd4) iss <= 1'b0; else cx <= cx + 3'd1;
            end else begin
              cj <= cj + 3'd1;
            end
          end
          dv <= iss; dx <= cx; dj <= cj;
          if (dv) begin
            if (dj == 3'd0)      begin T0 <= q0;                T1 <= q1;                end
            else if (dj == 3'd1) begin T0 <= T0 ^ rol(q0, 6'd1); T1 <= T1 ^ rol(q1, 6'd1); end
            if (dx == 3'd4 && dj == 3'd6) begin          // the last B lane written this clock
              ks <= K_CHI;
              cy <= 3'd0;
              cj <= 3'd0;
              cs <= 2'd0;
              dv <= 1'b0;
              T0 <= 64'd0; T1 <= 64'd0;
            end
          end
        end

        // ---- chi + iota: 4 clocks per lane ----
        K_CHI: begin
          case (cs)
            2'd0: cs <= 2'd1;
            2'd1: begin                                  // X = ~B[x+1] (NOT on share 0 only)
              X0r <= ~q0;
              X1r <= use1 ? q1 : 64'd0;
              cs  <= 2'd2;
            end
            2'd2: begin                                  // Y = B[x+2]
              Y0r <= q0;
              Y1r <= use1 ? q1 : 64'd0;
              cs  <= 2'd3;
            end
            default: begin                               // the AND (above); write-back next clock
              X0r <= 64'd0;
              X1r <= 64'd0;
              wbv <= 1'b1;
              wbi <= lidx(chx, cy);
              cs  <= 2'd0;
              if (cj == 3'd4) begin
                cj <= 3'd0;
                if (cy == 3'd4) begin                    // round complete
                  cy <= 3'd0;
                  if (rnd_i == 5'd23) begin
                    ks <= K_IDLE;
                  end else begin
                    rnd_i <= rnd_i + 5'd1;
                    ks    <= K_TH;
                    cx    <= 3'd0;
                    iss   <= 1'b1;
                    dv    <= 1'b0;
                  end
                end else begin
                  cy <= cy + 3'd1;
                end
              end else begin
                cj <= cj + 3'd1;
              end
            end
          endcase
        end

        default: ks <= K_IDLE;
      endcase
    end
  end
endmodule
