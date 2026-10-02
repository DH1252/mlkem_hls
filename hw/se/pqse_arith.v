// -----------------------------------------------------------------------------
// pqse_arith.v - modular arithmetic of the PQSE secure element.
//
//   pqse_mulred   a*b mod q, pipelined, latency 4, clock-enabled (the one and
//                 only modular multiplier of the polynomial unit)
//   pqse_modq24   floor(x * q / 2^24) for a 24-bit x, combinational (turns 24
//                 random bits into an almost uniform mask mod q: bias < 2^-12)
//
// pqse_mulred uses Barrett reduction with 5039 = floor(2^24 / q), the formula
// of mod_q() in src/poly.c that test/test_unit.c checks for every x < 2^24.
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
  // v5: floor(x * q / 2^24) instead of x mod q - the same use (a mask mod q
  // from 24 random bits) and the same bound on the bias (each value has
  // floor or ceil of 2^24 / q preimages, statistical distance < q / 2^24),
  // but q = 2^11 + 2^10 + 2^8 + 1, so three adds and no multiplier (the
  // Barrett version took two multipliers per instance, three instances)
  wire [35:0] xq = {1'b0, x, 11'd0} + {2'b0, x, 10'd0} + {4'd0, x, 8'd0} + {12'd0, x};
  assign r = xq[35:24];                      // 0 .. q-1
endmodule
