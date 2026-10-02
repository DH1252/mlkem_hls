// -----------------------------------------------------------------------------
// mlkem2_sample.v - samplers of the v2 core, fed by the Keccak engine.
//
//   mlkem2_parse   SampleNTT (FIPS 203 Alg. 7): 6 bytes (4 candidates) per
//                  clock, twice v1. Accepted coefficients collect in a small
//                  staging buffer; every 8 (an aligned group of 4 words) are
//                  written in one clock to the 4 banks.
//   mlkem2_cbd     SamplePolyCBD_2 (Alg. 8): one byte -> one word, 4 words per
//                  clock (a 64-bit lane in 2 clocks), aligned groups.
//
// Group a (a = 0..31) = words 4a..4a+3, all at bank address a. Word 4a+j is in
// bank {j[0], parity(a) ^ j[0] ^ j[1]} (see mlkem2_mem.v).
//
// UNTESTED FIRST VERSION - see hw/manual_v2/README.md.
// -----------------------------------------------------------------------------

module mlkem2_parse (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire        in_valid,
  input  wire [63:0] in_lane,
  output wire        in_ready,
  output wire        done,
  output reg  [19:0] waddr,
  output reg  [95:0] wdata,
  output reg  [3:0]  wen
);
  reg [127:0] sbuf;     // stream bytes, oldest in [7:0]
  reg   [4:0] bcnt;     // bytes held, 0..16
  reg [143:0] pbuf;     // accepted coefficients not yet written, oldest in [11:0]
  reg   [3:0] pc;       // how many (0..7 between clocks)
  reg   [5:0] gidx;     // groups written (32 = finished)

  wire        fin  = gidx[5];
  wire        can  = !fin && (bcnt >= 5'd6);
  wire  [7:0] b0 = sbuf[7:0],   b1 = sbuf[15:8],  b2 = sbuf[23:16];
  wire  [7:0] b3 = sbuf[31:24], b4 = sbuf[39:32], b5 = sbuf[47:40];
  wire [11:0] d1 = {b1[3:0], b0};
  wire [11:0] d2 = {b2, b1[7:4]};
  wire [11:0] d3 = {b4[3:0], b3};
  wire [11:0] d4 = {b5, b4[7:4]};

  // accept in stream order while fewer than 256 coefficients are taken
  wire  [8:0] n0 = {gidx[4:0], 3'b000} + {5'd0, pc};
  wire        a1 = can && (d1 < 12'd3329) && (n0 < 9'd256);
  wire  [8:0] n1 = n0 + {8'd0, a1};
  wire        a2 = can && (d2 < 12'd3329) && (n1 < 9'd256);
  wire  [8:0] n2 = n1 + {8'd0, a2};
  wire        a3 = can && (d3 < 12'd3329) && (n2 < 9'd256);
  wire  [8:0] n3 = n2 + {8'd0, a3};
  wire        a4 = can && (d4 < 12'd3329) && (n3 < 9'd256);
  wire  [2:0] kk = {2'd0, a1} + {2'd0, a2} + {2'd0, a3} + {2'd0, a4};

  // pack the accepted values (in order) into the low end of `accv`
  reg  [47:0] accv;
  reg   [2:0] pos;
  always @* begin
    accv = 48'd0;
    pos    = 3'd0;
    if (a1) begin accv[12*pos +: 12] = d1; pos = pos + 3'd1; end
    if (a2) begin accv[12*pos +: 12] = d2; pos = pos + 3'd1; end
    if (a3) begin accv[12*pos +: 12] = d3; pos = pos + 3'd1; end
    if (a4) begin accv[12*pos +: 12] = d4; pos = pos + 3'd1; end
  end

  wire [143:0] nbuf = pbuf | ({96'd0, accv} << (12 * pc));
  wire   [3:0] tot  = pc + {1'b0, kk};
  wire         wr   = (tot >= 4'd8);

  wire  [4:0] bc_a = can ? (bcnt - 5'd6) : bcnt;
  assign in_ready  = !fin && (bc_a <= 5'd8);
  wire        take = in_valid && in_ready;

  always @(posedge clk) begin
    if (rst || start) begin
      sbuf <= 128'd0;
      bcnt <= 5'd0;
      pbuf <= 144'd0;
      pc   <= 4'd0;
      gidx <= 6'd0;
    end else begin
      if (can || take) begin
        sbuf <= (can ? (sbuf >> 48) : sbuf)
              | (take ? ({64'd0, in_lane} << {bc_a, 3'b000}) : 128'd0);
        bcnt <= bc_a + (take ? 5'd8 : 5'd0);
      end
      if (kk != 3'd0) begin
        if (wr) begin
          pbuf <= nbuf >> 96;
          pc   <= tot - 4'd8;
          gidx <= gidx + 6'd1;
        end else begin
          pbuf <= nbuf;
          pc   <= tot;
        end
      end
    end
  end

  // group write, registered (shortens the path from the byte buffer to the RAM)
  integer j;
  reg [1:0] bk;
  always @(posedge clk) begin
    if (rst || start) begin
      wen <= 4'b0000;
    end else begin
      wen <= (kk != 3'd0 && wr) ? 4'b1111 : 4'b0000;
      if (kk != 3'd0 && wr) begin
        waddr <= {4{gidx[4:0]}};
        for (j = 0; j < 4; j = j + 1) begin
          bk = {j[0], (^gidx[4:0]) ^ j[0] ^ j[1]};
          wdata[24*bk +: 24] <= nbuf[24*j +: 24];
        end
      end
    end
  end

  assign done = fin && (wen == 4'b0000);
endmodule


module mlkem2_cbd (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire        in_valid,
  input  wire [63:0] in_lane,
  output wire        in_ready,
  output wire        done,
  output reg  [19:0] waddr,
  output reg  [95:0] wdata,
  output wire [3:0]  wen
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
  reg        h;       // which half (bytes 0-3 or 4-7)
  reg  [3:0] li;      // lane index
  reg  [4:0] la;      // lanes accepted

  assign in_ready = (la < 5'd16) && (!lv || h);
  wire   take     = in_valid && in_ready;

  always @(posedge clk) begin
    if (rst || start) begin
      lv <= 1'b0;
      la <= 5'd0;
      h  <= 1'b0;
    end else if (take) begin
      lane <= in_lane;
      lv   <= 1'b1;
      h    <= 1'b0;
      li   <= la[3:0];
      la   <= la + 5'd1;
    end else if (lv) begin
      if (h) lv <= 1'b0;
      h <= ~h;
    end
  end

  // group {li, h}: words 8li + 4h + j = bytes 4h + j of the lane
  wire [4:0] ga = {li, h};
  integer j;
  reg [1:0] bk;
  reg [7:0] by;
  always @* begin
    waddr = {4{ga}};
    wdata = 96'd0;
    for (j = 0; j < 4; j = j + 1) begin
      by = lane[8*(4*h + j) +: 8];
      bk = {j[0], (^ga) ^ j[0] ^ j[1]};
      wdata[24*bk +: 24] = {cbdv(by[7:4]), cbdv(by[3:0])};
    end
  end

  assign wen  = lv ? 4'b1111 : 4'b0000;
  assign done = (la == 5'd16) && !lv;
endmodule
