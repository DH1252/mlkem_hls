// -----------------------------------------------------------------------------
// pqse_keccak.v - first-order masked Keccak-f[1600], state in flip-flops (v1.6).
//
// v1.6 trades area for clocks and energy: the state is two 1600-bit registers,
// one per Boolean share (S0 ^ S1 = state), lane A[x + 5y] at bits
// [64(x + 5y) +: 64]. v4 / v1.5 kept it in two 64 x 65 RAMs and needed 3,050
// clocks per masked permutation (126 per round, about 150 RAM accesses each);
// here a masked permutation takes 168 clocks and an unmasked one 24, and no
// RAM is read or written.
//
// Masked round (7 clocks):
//   L       1 clock   S_s <= pi(rho(theta(S_s))), each share on its own
//                     (pqse_klin, linear). The B lanes are registered before
//                     chi uses them: theta mixes many lanes into every B lane,
//                     so an AND fed straight from the linear layer could see
//                     share 0 and share 1 of one A lane.
//   CHI     6 clocks  cy = 0..4: plane y = cy, all five lanes at once, one DOM
//                     AND per lane (Gross et al., TIS 2016), 320 fresh random bits:
//                       X = ~B[x+1] (NOT on share 0 only), Y = B[x+2]
//                       D00 = X0&Y0   D01 = X0&Y1 ^ r_x   D10 = X1&Y0 ^ r_x   D11 = X1&Y1
//                     registered; in the same clock (cy >= 1) plane cy - 1 is
//                     written back:
//                       S0[x, y] <= B0[x, y] ^ D00[x] ^ D01[x] (^ iota)
//                       S1[x, y] <= B1[x, y] ^ D11[x] ^ D10[x]
//                     cy = 5: plane 4 written back, the products load 0.
// Unmasked job (msk = 0: the XOF of A, H(ek)): one whole round per clock,
// S0 <= iota(chi(L(S0))); share 1 stays zero and is not clocked.
//
// Robust-probing argument (first order, glitches + transitions). Not yet in
// scripts/pqse_probe_verify.py, which models the v4 RAM schedule:
//   - The shares never meet outside the registered DOM cross terms. L, the
//     plane multiplexers, the absorb, the read-out and the parity checks are
//     built per share.
//   - The AND of lane x takes share 0 of column x + 1 and share 1 of column
//     x + 2 (or the reverse). The plane multiplexer may glitch to any plane,
//     but never to another column, so an AND gate never sees both shares of
//     one lane. Distinct B lanes are distinct outputs of an invertible linear
//     map, so their share-1 parts are jointly uniform; a written-back lane is
//     refreshed by its r_x.
//   - The products hold a value for one clock (each plane's own r) and are 0
//     outside CHI; the write-back cone of share s is B_s, D_ss, D_s(1-s).
//   - Operand isolation: the AND inputs are 0 outside the five AND clocks, L's
//     inputs are 0 outside the L clock (masked) and K_U (unmasked), and the
//     unmasked chi's inputs are 0 outside K_U. This also keeps the large XOR
//     networks still while the state changes plane by plane.
//
// Sponge interface as in v4 (pqse_sponge.v unchanged apart from the random
// word): ax_en XORs a lane into the state at the clock edge; rd_en loads lane
// rd_idx into the read registers (rd_v0 / rd_v1 from the next clock, held);
// clr wipes the state, the read registers and the products in one clock
// unless they are known to be clean.
//
// Fault detection: every lane of each share has a parity bit, loaded with the
// parity of the value written into the lane, and every clock the parity of
// every stored lane is compared with it (per share, registered separately).
// A flipped state bit raises perr in the next clock, also in the middle of a
// permutation. The control (state, round, plane) has complemented shadows.
//
// MASKED = 0: share 1, its linear layer and the AND cross terms are not built.
//
// UNTESTED FIRST VERSION - see hw/se_v1_6/README.md.
// -----------------------------------------------------------------------------
module pqse_keccak #(
  parameter MASKED   = 1,
  parameter RAMSTYLE = 0          // unused since v1.6 (no state RAM)
) (
  input  wire         clk,
  input  wire         rst,
  input  wire         msk,        // this job is masked
  // lane access while idle (pqse_sponge.v: never during a permutation or a
  // wipe, never together with go)
  input  wire         clr,        // keep the state zero: wipe it unless already clean (busy meanwhile)
  input  wire         ax_en,      // state[ax_idx] ^= {ax_v1, ax_v0}
  input  wire [4:0]   ax_idx,
  input  wire [63:0]  ax_v0,
  input  wire [63:0]  ax_v1,
  input  wire         rd_en,      // read lane rd_idx: on rd_v0 / rd_v1 from the next clock (held)
  input  wire [4:0]   rd_idx,
  output wire [63:0]  rd_v0,
  output wire [63:0]  rd_v1,
  // permutation
  input  wire         go,
  output wire         busy,
  input  wire [319:0] rnd,        // 64 fresh bits per lane of a plane (pqse_kprng)
  output wire         rnd_take,
  output wire         perr        // state parity or control mismatch: a fault
);
  localparam M1 = (MASKED != 0);

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

  // ---- state ---------------------------------------------------------------------------
  localparam [2:0] K_IDLE = 3'd0, K_L = 3'd1, K_CHI = 3'd2, K_U = 3'd3;
  reg  [2:0]    ks, ks_n;
  reg  [4:0]    rnd_i, rnd_i_n;   // round 0..23
  reg  [2:0]    cy, cy_n;         // CHI: 0..4 AND plane cy (and write plane cy - 1), 5 write plane 4
  reg           pctl;             // control mismatch (registered)
  reg           mj;               // latched msk of the running permutation
  reg           clean;            // state, read registers and products are zero
  wire [1599:0] S0, S1;           // the state, per share (registers r0 / r1 of g_lane[i])
  wire [24:0]   p0, p1;           // parity bit of every lane, per share (pb0 / pb1 of g_lane[i])
  reg           pe0, pe1;         // parity mismatch, per share (registered)
  reg  [319:0]  D00, D01, D10, D11;   // DOM products of the plane, lane x at [64x +: 64]
  reg  [63:0]   R0, R1;           // read registers

  wire use1   = M1 && mj;
  wire andclk = (ks == K_CHI) && (cy <= 3'd4);
  wire wipe   = (ks == K_IDLE) && !go && clr && !clean;
  assign busy     = go | (ks != K_IDLE) | (clr && !clean);
  assign rnd_take = andclk && use1;
  assign rd_v0    = R0;
  assign rd_v1    = M1 ? R1 : 64'd0;
  wire [63:0] rc  = rc_of(rnd_i);

  // ---- linear layer, one per share (inputs 0 when unused) ----------------------------------
  wire [1599:0] Li0 = ((ks == K_L) || (ks == K_U)) ? S0 : 1600'd0;
  wire [1599:0] Li1 = (M1 && (ks == K_L)) ? S1 : 1600'd0;
  wire [1599:0] L0, L1;
  pqse_klin u_l0 (.a(Li0), .b(L0));
  generate
    if (M1) begin : g_l1
      pqse_klin u_l1 (.a(Li1), .b(L1));
    end else begin : g_nl1
      assign L1 = 1600'd0;
    end
  endgenerate

  // ---- unmasked chi + iota (K_U only) ----------------------------------------------------------
  wire [1599:0] Ci = (ks == K_U) ? L0 : 1600'd0;
  wire [1599:0] U0;
  genvar gx, gy, gl;
  generate
    for (gl = 0; gl < 25; gl = gl + 1) begin : g_u
      localparam integer X = gl % 5, Y = gl / 5;
      localparam integer X1 = ((X + 1) % 5) + 5 * Y, X2 = ((X + 2) % 5) + 5 * Y;
      assign U0[64*gl +: 64] = Ci[64*gl +: 64] ^ (~Ci[64*X1 +: 64] & Ci[64*X2 +: 64]) ^
                               ((gl == 0) ? rc : 64'd0);
    end
  endgenerate

  // ---- masked chi: the plane of the AND clock, per share (0 outside the AND clocks) ----------
  reg  [319:0] P0, P1;
  always @* begin
    P0 = 320'd0; P1 = 320'd0;
    if (andclk) begin
      case (cy)
        3'd0: begin P0 = S0[   0 +: 320]; P1 = S1[   0 +: 320]; end
        3'd1: begin P0 = S0[ 320 +: 320]; P1 = S1[ 320 +: 320]; end
        3'd2: begin P0 = S0[ 640 +: 320]; P1 = S1[ 640 +: 320]; end
        3'd3: begin P0 = S0[ 960 +: 320]; P1 = S1[ 960 +: 320]; end
        default: begin P0 = S0[1280 +: 320]; P1 = S1[1280 +: 320]; end
      endcase
    end
    if (!use1) P1 = 320'd0;
  end
  wire [319:0] F00, F01, F10, F11;
  generate
    for (gx = 0; gx < 5; gx = gx + 1) begin : g_and
      localparam integer XA = (gx + 1) % 5, XB = (gx + 2) % 5;
      wire [63:0] x0 = ~P0[64*XA +: 64], y0 = P0[64*XB +: 64];
      wire [63:0] x1 =  P1[64*XA +: 64], y1 = P1[64*XB +: 64];
      wire [63:0] r  = use1 ? rnd[64*gx +: 64] : 64'd0;
      assign F00[64*gx +: 64] = x0 & y0;
      assign F01[64*gx +: 64] = (x0 & y1) ^ r;
      assign F10[64*gx +: 64] = (x1 & y0) ^ r;
      assign F11[64*gx +: 64] = x1 & y1;
    end
  endgenerate
  always @(posedge clk) begin
    if (rst) begin
      D00 <= 320'd0; D01 <= 320'd0; D10 <= 320'd0; D11 <= 320'd0;
    end else if ((ks == K_CHI) || wipe) begin
      D00 <= andclk ? F00 : 320'd0;
      D01 <= andclk ? F01 : 320'd0;
      D10 <= andclk ? F10 : 320'd0;
      D11 <= andclk ? F11 : 320'd0;
    end
  end

  // ---- per-lane write: one enable and one next value per lane (constant indices) -----------
  wire [1599:0] N0, N1;
  wire [24:0]   we0, we1;
  generate
    for (gl = 0; gl < 25; gl = gl + 1) begin : g_lane
      localparam integer X = gl % 5, Y = gl / 5;
      wire ab = (ks == K_IDLE) && ax_en && (ax_idx == gl);
      wire lw = (ks == K_L);
      wire uw = (ks == K_U);
      wire cw = (ks == K_CHI) && (cy == (Y + 1));            // chi write-back of plane Y
      wire [63:0] s0 = S0[64*gl +: 64], s1 = S1[64*gl +: 64];
      wire [63:0] io = ((gl == 0) && cw) ? rc : 64'd0;
      assign we0[gl] = wipe | ab | lw | uw | cw;
      assign we1[gl] = M1 && (wipe | (ab && msk) | (use1 && (lw | cw)));
      assign N0[64*gl +: 64] = wipe ? 64'd0 : ab ? (s0 ^ ax_v0) : lw ? L0[64*gl +: 64] :
                               uw ? U0[64*gl +: 64] :
                               (s0 ^ D00[64*X +: 64] ^ D01[64*X +: 64] ^ io);
      assign N1[64*gl +: 64] = wipe ? 64'd0 : ab ? (s1 ^ ax_v1) : lw ? L1[64*gl +: 64] :
                               (s1 ^ D11[64*X +: 64] ^ D10[64*X +: 64]);
      reg [63:0] r0, r1;                                   // lane gl, share 0 / share 1
      reg        pb0, pb1;                                 // its parity bits
      assign S0[64*gl +: 64] = r0;
      assign S1[64*gl +: 64] = r1;
      assign p0[gl] = pb0;
      assign p1[gl] = pb1;
      always @(posedge clk) begin
        if (rst) begin
          r0  <= 64'd0;
          pb0 <= 1'b0;
        end else if (we0[gl]) begin
          r0  <= N0[64*gl +: 64];
          pb0 <= ^N0[64*gl +: 64];
        end
        if (rst) begin
          r1  <= 64'd0;
          pb1 <= 1'b0;
        end else if (we1[gl]) begin
          r1  <= N1[64*gl +: 64];
          pb1 <= ^N1[64*gl +: 64];
        end
      end
    end
  endgenerate

  // ---- parity check of every stored lane, per share ---------------------------------------------
  wire [24:0] q0, q1;
  generate
    for (gl = 0; gl < 25; gl = gl + 1) begin : g_par
      assign q0[gl] = ^S0[64*gl +: 64];
      assign q1[gl] = M1 ? ^S1[64*gl +: 64] : 1'b0;
    end
  endgenerate
  wire ctl_bad = (ks != ~ks_n) | (rnd_i != ~rnd_i_n) | (cy != ~cy_n);
  assign perr = pe0 | pe1 | pctl;

  // ---- read registers ----------------------------------------------------------------------------
  reg [63:0] rl0, rl1;
  integer li;
  always @* begin
    rl0 = 64'd0; rl1 = 64'd0;
    for (li = 0; li < 25; li = li + 1)
      if (rd_idx == li) begin rl0 = S0[64*li +: 64]; rl1 = S1[64*li +: 64]; end
  end

  // ---- control ----------------------------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      begin ks    <= K_IDLE; ks_n    <= ~K_IDLE; end
      begin rnd_i <= 5'd0;   rnd_i_n <= ~5'd0;   end
      begin cy    <= 3'd0;   cy_n    <= ~3'd0;   end
      pctl  <= 1'b0;
      pe0   <= 1'b0;
      pe1   <= 1'b0;
      mj    <= 1'b0;
      clean <= 1'b1;
      R0    <= 64'd0;
      R1    <= 64'd0;
    end else begin
      pctl <= ctl_bad;
      pe0  <= (q0 != p0);
      pe1  <= (q1 != p1);
      if (wipe) begin
        R0 <= 64'd0;
        R1 <= 64'd0;
      end else if ((ks == K_IDLE) && rd_en) begin
        R0 <= rl0;
        R1 <= M1 ? rl1 : 64'd0;
      end
      case (ks)
        K_IDLE: begin
          if (ax_en) clean <= 1'b0;
          if (go) begin
            mj    <= msk;
            clean <= 1'b0;
            begin rnd_i <= 5'd0; rnd_i_n <= ~5'd0; end
            begin cy    <= 3'd0; cy_n    <= ~3'd0; end
            if (M1 && msk) begin ks <= K_L; ks_n <= ~K_L; end
            else           begin ks <= K_U; ks_n <= ~K_U; end
          end else if (wipe) begin
            clean <= 1'b1;
          end
        end
        K_L: begin
          begin ks <= K_CHI; ks_n <= ~K_CHI; end
          begin cy <= 3'd0;  cy_n <= ~3'd0;  end
        end
        K_CHI: begin
          if (cy == 3'd5) begin                           // plane 4 written: round complete
            begin cy <= 3'd0; cy_n <= ~3'd0; end
            if (rnd_i == 5'd23) begin
              begin ks <= K_IDLE; ks_n <= ~K_IDLE; end
            end else begin
              begin rnd_i <= rnd_i + 5'd1; rnd_i_n <= ~(rnd_i + 5'd1); end
              begin ks    <= K_L;          ks_n    <= ~K_L; end
            end
          end else begin
            begin cy <= cy + 3'd1; cy_n <= ~(cy + 3'd1); end
          end
        end
        K_U: begin
          if (rnd_i == 5'd23) begin
            begin ks <= K_IDLE; ks_n <= ~K_IDLE; end
          end else begin
            begin rnd_i <= rnd_i + 5'd1; rnd_i_n <= ~(rnd_i + 5'd1); end
          end
        end
        default: begin ks <= K_IDLE; ks_n <= ~K_IDLE; end
      endcase
    end
  end
endmodule


// pi(rho(theta(a))) of a 1600-bit state, lane i = x + 5y at [64i +: 64]
module pqse_klin (
  input  wire [1599:0] a,
  output wire [1599:0] b
);
  // rotation offset of lane i = x + 5y (FIPS 202 Table 2)
  function integer rho_c(input integer i);
    case (i)
      0:  rho_c = 0;   1:  rho_c = 1;   2:  rho_c = 62;  3:  rho_c = 28;  4:  rho_c = 27;
      5:  rho_c = 36;  6:  rho_c = 44;  7:  rho_c = 6;   8:  rho_c = 55;  9:  rho_c = 20;
      10: rho_c = 3;   11: rho_c = 10;  12: rho_c = 43;  13: rho_c = 25;  14: rho_c = 39;
      15: rho_c = 41;  16: rho_c = 45;  17: rho_c = 15;  18: rho_c = 21;  19: rho_c = 8;
      20: rho_c = 18;  21: rho_c = 2;   22: rho_c = 61;  23: rho_c = 56;  default: rho_c = 14;
    endcase
  endfunction
  // pi: lane (x, y) goes to (y, 2x + 3y), index y + 5((2x + 3y) mod 5)
  function integer pdst_c(input integer i);
    pdst_c = (i / 5) + 5 * ((2 * (i % 5) + 3 * (i / 5)) % 5);
  endfunction

  wire [319:0] c, d;
  genvar gx, gl;
  generate
    for (gx = 0; gx < 5; gx = gx + 1) begin : g_c
      assign c[64*gx +: 64] = a[64*gx +: 64] ^ a[64*(gx+5) +: 64] ^ a[64*(gx+10) +: 64] ^
                              a[64*(gx+15) +: 64] ^ a[64*(gx+20) +: 64];
    end
    for (gx = 0; gx < 5; gx = gx + 1) begin : g_d
      localparam integer XM = (gx + 4) % 5, XP = (gx + 1) % 5;
      wire [63:0] cp = c[64*XP +: 64];
      assign d[64*gx +: 64] = c[64*XM +: 64] ^ {cp[62:0], cp[63]};
    end
    for (gl = 0; gl < 25; gl = gl + 1) begin : g_rp
      localparam integer R = rho_c(gl);
      localparam integer P = pdst_c(gl);
      wire [63:0]  t  = a[64*gl +: 64] ^ d[64*(gl % 5) +: 64];
      wire [127:0] tt = {t, t};
      assign b[64*P +: 64] = tt[127-R -: 64];                // rotate left by R
    end
  endgenerate
endmodule
