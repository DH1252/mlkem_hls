// -----------------------------------------------------------------------------
// pqse_arith.v - modular arithmetic of the PQSE secure element.
//
//   pqse_mulred   a*b mod q, pipelined, latency 4, clock-enabled (the one and
//                 only modular multiplier of the polynomial unit)
//   pqse_modq24   x mod q for a 24-bit x, combinational (turns 24 random bits
//                 into an almost uniform mask mod q: bias < 2^-12)
//
// Both use Barrett reduction with 5039 = floor(2^24 / q), the formula of
// mod_q() in src/poly.c that test/test_unit.c checks for every x < 2^24.
//
// UNTESTED FIRST VERSION - see hw/se/README.md.
// -----------------------------------------------------------------------------
module pqse_mulred (
  input  wire        clk,
  input  wire        en,        // advance the pipeline (hold it still when idle)
  input  wire [11:0] a,
  input  wire [11:0] b,
  output wire [11:0] r          // a*b mod q, 4 enabled clocks after a, b
);
  reg  [23:0] p1, p2;
  reg  [12:0] t2, r3;
  reg  [11:0] r4;
  wire [36:0] m1  = p1 * 37'd5039;          // t = floor(p * 5039 / 2^24)
  wire [24:0] tq  = t2 * 25'd3329;
  wire [24:0] dif = {1'b0, p2} - tq;         // p - t*q, in 0 .. 2q-1
  wire [12:0] r3s = r3 - 13'd3329;

  always @(posedge clk) begin
    if (en) begin
      p1 <= a * b;
      p2 <= p1;
      t2 <= m1[36:24];
      r3 <= dif[12:0];
      r4 <= (r3 >= 13'd3329) ? r3s[11:0] : r3[11:0];
    end
  end

  assign r = r4;
endmodule


module pqse_modq24 (
  input  wire [23:0] x,
  output wire [11:0] r
);
  wire [36:0] m   = x * 37'd5039;
  wire [12:0] t   = m[36:24];
  wire [24:0] tq  = t * 25'd3329;
  wire [24:0] dif = {1'b0, x} - tq;          // 0 .. 2q-1
  wire [12:0] d13 = dif[12:0];
  wire [12:0] ds  = d13 - 13'd3329;
  assign r = (d13 >= 13'd3329) ? ds[11:0] : d13[11:0];
endmodule
