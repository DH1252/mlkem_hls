// -----------------------------------------------------------------------------
// pqse_sample.v - unmasked samplers fed by the sponge's lane stream.
//
//   pqse_parse   SampleNTT (FIPS 203 Alg. 7): 3 bytes -> two 12-bit candidates
//                per clock, values < q kept, one word {c[2w+1], c[2w]} written
//                per accepted pair, until 256 coefficients
//   pqse_cbd     SamplePolyCBD_2 (Alg. 8): one byte per clock -> one word
//                (low nibble -> even coefficient, high nibble -> odd), 16 lanes
//
// Both write the polynomial RAM through one port: waddr = {slot, word}.
// Used for public values (matrix entries) and for the unmasked operations
// (KeyGen, Encaps). The masked CBD of Decaps is in pqse_masked.v.
//
// UNTESTED FIRST VERSION - see hw/se/README.md.
// -----------------------------------------------------------------------------
module pqse_parse (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [3:0]  slot,
  input  wire        in_valid,
  input  wire [63:0] in_lane,
  output wire        in_ready,
  output wire        done,
  output wire        we,
  output wire [10:0] waddr,
  output wire [23:0] wdata
);
  reg [127:0] sbuf;    // stream bytes, oldest in [7:0]
  reg   [4:0] bcnt;    // bytes held (0..16)
  reg   [8:0] n;       // coefficients accepted
  reg  [11:0] pend;    // an accepted coefficient waiting for its partner
  reg         pv;
  reg   [6:0] widx;    // next word to write
  reg         fin;
  reg   [3:0] sl;

  wire        can  = !fin && (bcnt >= 5'd3);
  // the next 3 bytes b0 b1 b2 = sbuf[23:0]: d1 = {b1[3:0], b0}, d2 = {b2, b1[7:4]}
  wire [11:0] d1   = sbuf[11:0];
  wire [11:0] d2   = sbuf[23:12];
  wire        a1   = can && (d1 < 12'd3329);
  wire  [8:0] n1   = n + {8'd0, a1};
  wire        a2   = can && (d2 < 12'd3329) && (n1 < 9'd256);
  wire  [8:0] nn   = n1 + {8'd0, a2};
  wire  [4:0] bc_a = can ? (bcnt - 5'd3) : bcnt;
  assign in_ready  = !fin && (bc_a <= 5'd8);
  wire        take = in_valid && in_ready;
  // the new lane placed after the bc_a bytes still held: a take needs
  // bc_a <= 8, so 9 placements (an explicit mux instead of a 128-bit shift by
  // {bc_a, 3'b000}, which GowinSynthesis fails on with SP00018 "error bus name set")
  reg [127:0] ins;
  always @* begin
    case (bc_a[3:0])
      4'd0:    ins = {64'd0, in_lane};
      4'd1:    ins = {56'd0, in_lane,  8'd0};
      4'd2:    ins = {48'd0, in_lane, 16'd0};
      4'd3:    ins = {40'd0, in_lane, 24'd0};
      4'd4:    ins = {32'd0, in_lane, 32'd0};
      4'd5:    ins = {24'd0, in_lane, 40'd0};
      4'd6:    ins = {16'd0, in_lane, 48'd0};
      4'd7:    ins = { 8'd0, in_lane, 56'd0};
      4'd8:    ins = {       in_lane, 64'd0};
      default: ins = 128'd0;                     // never taken (bc_a > 8: no take)
    endcase
  end

  // accepted values in stream order: pend (if any), d1 (if a1), d2 (if a2)
  wire  [1:0] kk   = {1'b0, pv} + {1'b0, a1} + {1'b0, a2};
  wire [11:0] v0   = pv ? pend : (a1 ? d1 : d2);
  wire [11:0] v1   = pv ? (a1 ? d1 : d2) : d2;
  wire        wr   = (kk >= 2'd2);

  assign we    = wr;
  assign waddr = {sl, widx};
  assign wdata = wr ? {v1, v0} : 24'd0;
  assign done  = fin;

  always @(posedge clk) begin
    if (rst || start) begin
      bcnt <= 5'd0;
      n    <= 9'd0;
      pv   <= 1'b0;
      widx <= 7'd0;
      fin  <= 1'b0;
      sbuf <= 128'd0;
      if (start) sl <= slot;
    end else begin
      if (can || take)
        sbuf <= (can ? (sbuf >> 24) : sbuf)
              | (take ? ins : 128'd0);
      bcnt <= bc_a + (take ? 5'd8 : 5'd0);
      n    <= nn;
      if (nn == 9'd256) fin <= 1'b1;
      if (wr) widx <= widx + 7'd1;
      case (kk)
        2'd0: begin end
        2'd1: begin pend <= v0; pv <= 1'b1; end
        2'd2: pv <= 1'b0;
        default: begin pend <= d2; pv <= 1'b1; end
      endcase
    end
  end
endmodule


module pqse_cbd (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [3:0]  slot,
  input  wire        in_valid,
  input  wire [63:0] in_lane,
  output wire        in_ready,
  output wire        done,
  output wire        we,
  output wire [10:0] waddr,
  output wire [23:0] wdata
);
  function [11:0] cbdv(input [3:0] nb);
    reg [1:0] x, y;
    begin
      x = {1'b0, nb[0]} + {1'b0, nb[1]};
      y = {1'b0, nb[2]} + {1'b0, nb[3]};
      if (x >= y) cbdv = {10'd0, x - y};
      else        cbdv = 12'd3329 - {10'd0, y - x};
    end
  endfunction

  reg [63:0] lane;
  reg        lv;      // a lane is being written
  reg  [2:0] c;       // byte within the lane
  reg  [4:0] la;      // lanes accepted
  reg  [3:0] sl;

  assign in_ready = (la < 5'd16) && (!lv || (c == 3'd7));
  wire   take     = in_valid && in_ready;

  wire [7:0] by = lane[8*c +: 8];
  assign we    = lv;
  assign waddr = {sl, la[3:0] - 4'd1, c};       // word = 8 * lane + byte
  assign wdata = lv ? {cbdv(by[7:4]), cbdv(by[3:0])} : 24'd0;
  assign done  = (la == 5'd16) && !lv;

  always @(posedge clk) begin
    if (rst || start) begin
      lv <= 1'b0;
      la <= 5'd0;
      c  <= 3'd0;
      if (start) sl <= slot;
    end else if (take) begin
      lane <= in_lane;
      lv   <= 1'b1;
      c    <= 3'd0;
      la   <= la + 5'd1;
    end else if (lv) begin
      if (c == 3'd7) lv <= 1'b0;
      c <= c + 3'd1;
    end
  end
endmodule
