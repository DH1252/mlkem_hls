// -----------------------------------------------------------------------------
// mlkem2_arith.v - modular arithmetic units of the v2 core (same math as v1,
// hw/manual/mlkem_rtl_arith.v, with valid-gated pipelines).
//
//   mlkem2_mulred   a*b mod q, latency 4
//   mlkem2_bfu      NTT (CT) / INTT (GS, halving) butterfly, latency 5
//   mlkem2_basemul  FIPS 203 base-case multiply-accumulate, latency 10
//
// Low power: every pipeline register has a clock enable driven by a valid
// bit travelling with the data. When a unit has no work, none of its
// registers load, so the multipliers and adders behind them do not switch.
// (FPGA: LAB clock enables; ASIC: the enables let the synthesis tool insert
// clock-gating cells.) Results are only defined in clocks where the
// corresponding valid bit is set.
//
// UNTESTED FIRST VERSION - see hw/manual_v2/README.md.
// -----------------------------------------------------------------------------

// a*b mod q (q = 3329) for a, b < q. Barrett with 5039 = floor(2^24 / q), as
// mod_q() in src/poly.c. Inputs sampled when en = 1; r valid 4 clocks later.
module mlkem2_mulred (
  input  wire        clk,
  input  wire        en,
  input  wire [11:0] a,
  input  wire [11:0] b,
  output wire [11:0] r
);
  reg  [2:0]  v;
  reg  [23:0] p1, p2;
  reg  [12:0] t2, r3;
  reg  [11:0] r4;
  wire [36:0] m1  = p1 * 37'd5039;
  wire [24:0] tq  = t2 * 25'd3329;
  wire [24:0] dif = {1'b0, p2} - tq;       // 0 .. 2q-1
  wire [12:0] r3s = r3 - 13'd3329;

  always @(posedge clk) begin
    v <= {v[1:0], en};
    if (en)   p1 <= a * b;
    if (v[0]) begin
      p2 <= p1;
      t2 <= m1[36:24];
    end
    if (v[1]) r3 <= dif[12:0];
    if (v[2]) r4 <= (r3 >= 13'd3329) ? r3s[11:0] : r3[11:0];
  end

  assign r = r4;
endmodule


// Butterfly. NTT: oa = a + z*b, ob = a - z*b. INTT: oa = (a+b)/2,
// ob = z*(b-a)/2 (seven halving layers give the 1/128 of FIPS 203 Alg. 10).
// Inputs sampled when en = 1 (clock T); outputs valid in clock T+5.
// `intt` must be stable for the whole operation.
module mlkem2_bfu (
  input  wire        clk,
  input  wire        en,
  input  wire        intt,
  input  wire [11:0] a,
  input  wire [11:0] b,
  input  wire [11:0] z,
  output wire [11:0] oa,
  output wire [11:0] ob
);
  function [11:0] addq(input [11:0] x, input [11:0] y);
    reg [12:0] s, t;
    begin
      s = {1'b0, x} + {1'b0, y};
      t = s - 13'd3329;
      addq = (s >= 13'd3329) ? t[11:0] : s[11:0];
    end
  endfunction

  function [11:0] subq(input [11:0] x, input [11:0] y);
    reg [12:0] s, t;
    begin
      s = {1'b0, x} + 13'd3329 - {1'b0, y};
      t = s - 13'd3329;
      subq = (s >= 13'd3329) ? t[11:0] : s[11:0];
    end
  endfunction

  // INTT first stage without chained adders. halfq(addq(x, y)) and
  // halfq(subq(y, x)) would be three adders in a row. Because q is odd, the
  // result is always one of three sums that can be computed side by side
  // from x and y; the parity (x[0] ^ y[0]) and one sign bit pick it:
  //   (x + y)/2 mod q:  S = x+y even -> S/2;  odd -> (S+q)/2 if S < q, else (S-q)/2
  //   (y - x)/2 mod q:  D = y-x odd  -> (D+q)/2;  even -> D/2 if D >= 0, else (D+2q)/2
  function [11:0] addhalf(input [11:0] x, input [11:0] y);   // (x + y) / 2 mod q
    reg [13:0] s, sp, sm;
    begin
      s  = {2'b00, x} + {2'b00, y};
      sp = {2'b00, x} + {2'b00, y} + 14'd3329;
      sm = {2'b00, x} + {2'b00, y} - 14'd3329;
      if (!(x[0] ^ y[0])) addhalf = s[12:1];
      else if (sm[13])    addhalf = sp[12:1];
      else                addhalf = sm[12:1];
    end
  endfunction

  function [11:0] subhalf(input [11:0] y, input [11:0] x);   // (y - x) / 2 mod q
    reg [13:0] d, dp, d2;
    begin
      d  = {2'b00, y} - {2'b00, x};
      dp = {2'b00, y} - {2'b00, x} + 14'd3329;
      d2 = {2'b00, y} - {2'b00, x} + 14'd6658;
      if (x[0] ^ y[0]) subhalf = dp[12:1];
      else if (d[13])  subhalf = d2[12:1];
      else             subhalf = d[12:1];
    end
  endfunction

  reg  [4:1]  v;                    // v[k]: the item sampled at T is at stage k
  reg  [11:0] a1, a2, a3, a4;       // NTT: a delayed to meet z*b
  reg  [11:0] s1, s2, s3, s4, s5;   // INTT: (a+b)/2 delayed
  reg  [11:0] d1, z1;               // INTT: (b-a)/2 and z for the multiplier
  reg  [11:0] o_add, o_sub;
  wire [11:0] r;

  // NTT: multiplier fed in T with (z, b); INTT: fed in T+1 with (z1, d1)
  mlkem2_mulred u_mul (
    .clk(clk),
    .en (intt ? v[1] : en),
    .a  (intt ? z1 : z),
    .b  (intt ? d1 : b),
    .r  (r)
  );

  always @(posedge clk) begin
    v <= {v[3:1], en};
    if (intt) begin
      if (en) begin
        s1 <= addhalf(a, b);       // = halfq(addq(a, b)), one adder level
        d1 <= subhalf(b, a);       // = halfq(subq(b, a)), one adder level
        z1 <= z;
      end
      if (v[1]) s2 <= s1;
      if (v[2]) s3 <= s2;
      if (v[3]) s4 <= s3;
      if (v[4]) s5 <= s4;
    end else begin
      if (en)   a1 <= a;
      if (v[1]) a2 <= a1;
      if (v[2]) a3 <= a2;
      if (v[3]) a4 <= a3;
      if (v[4]) begin
        o_add <= addq(a4, r);
        o_sub <= subq(a4, r);
      end
    end
  end

  assign oa = intt ? s5 : o_add;
  assign ob = intt ? r  : o_sub;
endmodule


// e = c0 + a0*b0 + (a1*b1)*g,  o = c1 + a0*b1 + a1*b0   (FIPS 203 Alg. 12)
// Inputs sampled when en = 1 (clock T); outputs valid in clock T+10.
module mlkem2_basemul (
  input  wire        clk,
  input  wire        en,
  input  wire [11:0] a0,
  input  wire [11:0] a1,
  input  wire [11:0] b0,
  input  wire [11:0] b1,
  input  wire [11:0] c0,
  input  wire [11:0] c1,
  input  wire [11:0] g,
  output wire [11:0] e,
  output wire [11:0] o
);
  function [11:0] addq(input [11:0] x, input [11:0] y);
    reg [12:0] s, t;
    begin
      s = {1'b0, x} + {1'b0, y};
      t = s - 13'd3329;
      addq = (s >= 13'd3329) ? t[11:0] : s[11:0];
    end
  endfunction

  reg  [9:1]  v;
  wire [11:0] m00, m11, m01, m10, mg;
  reg  [11:0] g1, g2, g3, g4;
  reg  [11:0] m00_5, m00_6, m00_7, m00_8;
  reg  [11:0] cr5, cr6, cr7, cr8;
  reg  [11:0] c0d [1:9];
  reg  [11:0] c1d [1:8];
  reg  [11:0] e9, o9, e10, o10;
  integer k;

  mlkem2_mulred u00 (.clk(clk), .en(en),   .a(a0),  .b(b0), .r(m00));   // T+4
  mlkem2_mulred u11 (.clk(clk), .en(en),   .a(a1),  .b(b1), .r(m11));   // T+4
  mlkem2_mulred u01 (.clk(clk), .en(en),   .a(a0),  .b(b1), .r(m01));   // T+4
  mlkem2_mulred u10 (.clk(clk), .en(en),   .a(a1),  .b(b0), .r(m10));   // T+4
  mlkem2_mulred ug  (.clk(clk), .en(v[4]), .a(m11), .b(g4), .r(mg));    // T+8

  always @(posedge clk) begin
    v <= {v[8:1], en};
    if (en) begin
      g1     <= g;
      c0d[1] <= c0;
      c1d[1] <= c1;
    end
    if (v[1]) g2 <= g1;
    if (v[2]) g3 <= g2;
    if (v[3]) g4 <= g3;
    for (k = 1; k <= 8; k = k + 1)
      if (v[k]) c0d[k+1] <= c0d[k];
    for (k = 1; k <= 7; k = k + 1)
      if (v[k]) c1d[k+1] <= c1d[k];
    if (v[4]) begin
      m00_5 <= m00;
      cr5   <= addq(m01, m10);
    end
    if (v[5]) begin m00_6 <= m00_5; cr6 <= cr5; end
    if (v[6]) begin m00_7 <= m00_6; cr7 <= cr6; end
    if (v[7]) begin m00_8 <= m00_7; cr8 <= cr7; end
    if (v[8]) begin
      e9 <= addq(m00_8, mg);
      o9 <= addq(cr8, c1d[8]);
    end
    if (v[9]) begin
      e10 <= addq(e9, c0d[9]);
      o10 <= o9;
    end
  end

  assign e = e10;
  assign o = o10;
endmodule
