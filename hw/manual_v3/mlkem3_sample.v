// -----------------------------------------------------------------------------
// mlkem3_sample.v - samplers of the v3 core, fed from the Keccak engine's
// block buffer (mlkem3_hash.v).
//
//   mlkem3_parse   SampleNTT (FIPS 203 Alg. 7): 12 bytes = 8 candidates per
//                  clock (v2: 6 bytes). A SHAKE128 block (168 bytes) is 14
//                  chunks, which matches a permutation at 2 rounds/clock.
//                  Three pipeline stages: split + compare, compact the
//                  accepted values, stage and write aligned 4-word groups.
//   mlkem3_cbd     SamplePolyCBD_2 (Alg. 8): 4 bytes -> one aligned group of
//                  4 words per clock (v2: a 64-bit lane in 2 clocks).
//
// Aligned group a = words 4a..4a+3 at bank address a; word 4a+j is in bank
// bank_of(4a+j) (mlkem3_mem.v).
//
// UNTESTED FIRST VERSION of v3 - see hw/manual_v3/README.md.
// -----------------------------------------------------------------------------

module mlkem3_parse (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire        in_valid,
  input  wire [95:0] in_chunk,     // 12 stream bytes, first in [7:0]
  output wire        full,         // 256 coefficients taken: stop feeding
  output wire        done,         // ... and all written
  output reg  [19:0] waddr,
  output reg  [95:0] wdata,
  output reg  [3:0]  wen
);
  function [1:0] bank_of(input [6:0] w);
    bank_of = {^(w & 7'b0101010), ^(w & 7'b1010101)};
  endfunction

  // --- stage A: 8 candidates, compare with q ---------------------------------
  // bytes b0 b1 b2 of each 3-byte group give d1 = b0 + 256*(b1 mod 16) and
  // d2 = (b1 >> 4) + 16*b2
  reg  [95:0] ca;     // candidate k at [12*k +: 12], stream order
  reg   [7:0] aa;     // accepted (< q)
  reg         va;
  integer m, k, n;
  reg  [11:0] d1, d2;
  reg  [95:0] ca_n;
  reg   [7:0] aa_n;

  always @* begin
    ca_n = 96'd0;
    aa_n = 8'd0;
    for (m = 0; m < 4; m = m + 1) begin
      d1 = {in_chunk[24*m + 11 -: 4], in_chunk[24*m +: 8]};
      d2 = {in_chunk[24*m + 16 +: 8], in_chunk[24*m + 12 +: 4]};
      ca_n[24*m +: 12]      = d1;
      ca_n[24*m + 12 +: 12] = d2;
      aa_n[2*m]             = (d1 < 12'd3329);
      aa_n[2*m + 1]         = (d2 < 12'd3329);
    end
  end

  always @(posedge clk) begin
    if (rst || start) va <= 1'b0;
    else              va <= in_valid;
    if (in_valid) begin
      ca <= ca_n;
      aa <= aa_n;
    end
  end

  // --- stage B: compact the accepted candidates (in order) --------------------
  reg  [95:0] pb;     // accepted values, packed from [11:0]
  reg   [3:0] kb;     // how many (0..8)
  reg         vb;
  reg   [2:0] pre [0:7];
  reg   [3:0] cntk;
  reg  [95:0] pb_n;

  always @* begin
    cntk = 4'd0;
    for (k = 0; k < 8; k = k + 1) begin
      pre[k] = cntk[2:0];                 // accepted before candidate k
      cntk   = cntk + {3'd0, aa[k]};
    end
    pb_n = 96'd0;
    for (n = 0; n < 8; n = n + 1)         // output slot n
      for (k = 0; k < 8; k = k + 1)
        if (aa[k] && (pre[k] == n))
          pb_n[12*n +: 12] = ca[12*k +: 12];
  end

  always @(posedge clk) begin
    if (rst || start) vb <= 1'b0;
    else              vb <= va;
    if (va) begin
      pb <= pb_n;
      kb <= cntk;
    end
  end

  // --- stage C: staging buffer, aligned group writes ---------------------------
  reg [191:0] sb;     // up to 15 values, oldest in [11:0]
  reg   [3:0] pc;     // values held between clocks (0..7)
  reg   [5:0] gidx;   // groups written (32 = finished)

  assign full = gidx[5];
  wire [191:0] nbuf = sb | ({96'd0, pb} << (12 * pc));
  wire   [4:0] tot  = {1'b0, pc} + {1'b0, kb};
  wire         wr   = vb && !full && (tot >= 5'd8);

  always @(posedge clk) begin
    if (rst || start) begin
      sb   <= 192'd0;
      pc   <= 4'd0;
      gidx <= 6'd0;
    end else if (vb && !full) begin
      if (wr) begin
        sb   <= nbuf >> 96;
        pc   <= tot[3:0] - 4'd8;
        gidx <= gidx + 6'd1;
      end else begin
        sb   <= nbuf;
        pc   <= tot[3:0];
      end
    end
  end

  integer j;
  reg [1:0] bk;
  always @(posedge clk) begin
    if (rst || start) begin
      wen <= 4'b0000;
    end else begin
      wen <= wr ? 4'b1111 : 4'b0000;
      if (wr) begin
        waddr <= {4{gidx[4:0]}};
        for (j = 0; j < 4; j = j + 1) begin
          bk = bank_of({gidx[4:0], 2'b00} | j);
          wdata[24*bk +: 24] <= nbuf[24*j +: 24];
        end
      end
    end
  end

  assign done = full && (wen == 4'b0000);
endmodule


module mlkem3_cbd (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire        in_valid,
  input  wire [31:0] in_chunk,     // stream bytes 4g .. 4g+3
  input  wire [4:0]  in_group,     // g
  output reg  [19:0] waddr,
  output reg  [95:0] wdata,
  output reg  [3:0]  wen
);
  function [1:0] bank_of(input [6:0] w);
    bank_of = {^(w & 7'b0101010), ^(w & 7'b1010101)};
  endfunction

  // one nibble -> one coefficient: (b0 + b1) - (b2 + b3) mod q
  function [11:0] cbdv(input [3:0] nb);
    reg [1:0] x, y;
    begin
      x = {1'b0, nb[0]} + {1'b0, nb[1]};
      y = {1'b0, nb[2]} + {1'b0, nb[3]};
      if (x >= y) cbdv = {10'd0, x - y};
      else        cbdv = 12'd3329 - {10'd0, y - x};
    end
  endfunction

  // byte i -> word i = {coefficient 2i+1 (high nibble), coefficient 2i}
  integer j;
  reg [1:0] bk;
  reg [7:0] by;
  always @(posedge clk) begin
    if (rst || start) begin
      wen <= 4'b0000;
    end else begin
      wen <= in_valid ? 4'b1111 : 4'b0000;
      if (in_valid) begin
        waddr <= {4{in_group}};
        for (j = 0; j < 4; j = j + 1) begin
          by = in_chunk[8*j +: 8];
          bk = bank_of({in_group, 2'b00} | j);
          wdata[24*bk +: 24] <= {cbdv(by[7:4]), cbdv(by[3:0])};
        end
      end
    end
  end
endmodule
