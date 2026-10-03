// -----------------------------------------------------------------------------
// pqse_arith.v - modular arithmetic of the PQSE secure element (v1.5).
//
//   pqse_mulred   a*b mod q, pipelined, latency 4, clock-enabled (the one and
//                 only modular multiplier of the polynomial unit)
//   pqse_modq24   x mod q for a 24-bit x, combinational (turns 24 random bits
//                 into an almost uniform mask mod q: bias < 2^-12)
//
// Reduction without multipliers (v1.5; v4 used Barrett reduction, two constant
// multiplications of 37 and 25 bits). q = 3329 = 2^12 - 2^9 - 2^8 + 1, so each
// bit k >= 12 of a 24-bit x stands for a small constant 2^k mod q, taken in
// (-q/2, q/2):
//   bit 12   767   13  1534   14  -261   15  -522   16 -1044   17  1241
//   bit 18  -847   19  1635   20   -59   21  -118   22  -236   23  -472
// y = x[11:0] + sum of the constants of the set bits + 2q lies in 3099 ..
// 15930 (14 bits) and y = x (mod q); four comparisons with q, 2q, 3q, 4q and
// one subtraction give x mod q. Exact for every x < 2^24 (checked
// exhaustively in Python; the same folding as HOPE-MLKEM, TCHES 2026(2),
// section 3.2.3).
// -----------------------------------------------------------------------------

// y = x (mod q), 3099 <= y <= 15930
module pqse_fold24 (
  input  wire [23:0] x,
  output wire [13:0] y
);
  wire [14:0] p = {3'd0, x[11:0]}
                + (x[12] ? 15'd767  : 15'd0) + (x[13] ? 15'd1534 : 15'd0)
                + (x[17] ? 15'd1241 : 15'd0) + (x[19] ? 15'd1635 : 15'd0)
                + 15'd6658;                                            // + 2q
  wire [12:0] n = (x[14] ? 13'd261  : 13'd0) + (x[15] ? 13'd522  : 13'd0)
                + (x[16] ? 13'd1044 : 13'd0) + (x[18] ? 13'd847  : 13'd0)
                + (x[20] ? 13'd59   : 13'd0) + (x[21] ? 13'd118  : 13'd0)
                + (x[22] ? 13'd236  : 13'd0) + (x[23] ? 13'd472  : 13'd0);
  wire [14:0] s = p - {2'd0, n};
  assign y = s[13:0];
endmodule

// y mod q for 0 <= y < 5q
module pqse_red5q (
  input  wire [13:0] y,
  output wire [11:0] r
);
  wire [13:0] c = (y >= 14'd13316) ? 14'd13316 : (y >= 14'd9987) ? 14'd9987 :
                  (y >= 14'd6658)  ? 14'd6658  : (y >= 14'd3329) ? 14'd3329 : 14'd0;
  wire [13:0] d = y - c;
  assign r = d[11:0];
endmodule


module pqse_mulred (
  input  wire        clk,
  input  wire        en,        // advance the pipeline (hold it still when idle)
  input  wire [11:0] a,
  input  wire [11:0] b,
  output wire [11:0] r          // a*b mod q, 4 enabled clocks after a, b
);
  reg  [23:0] p1;
  reg  [13:0] y2;
  reg  [11:0] r3, r4;
  wire [13:0] yf;
  wire [11:0] rf;
  pqse_fold24 u_f (.x(p1), .y(yf));
  pqse_red5q  u_r (.y(y2), .r(rf));

  always @(posedge clk) begin
    if (en) begin
      p1 <= a * b;
      y2 <= yf;
      r3 <= rf;
      r4 <= r3;
    end
  end

  assign r = r4;
endmodule


module pqse_modq24 (
  input  wire [23:0] x,
  output wire [11:0] r
);
  wire [13:0] y;
  pqse_fold24 u_f (.x(x), .y(y));
  pqse_red5q  u_r (.y(y), .r(r));
endmodule
