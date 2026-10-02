// -----------------------------------------------------------------------------
// pqse_sample.v - unmasked samplers fed by the sponge's lane stream.
//
//   pqse_parse   SampleNTT (FIPS 203 Alg. 7): byte-serial, 3 bytes -> two 12-bit
//                candidates every 3 clocks, values < q kept, one word
//                {c[2w+1], c[2w]} written per accepted pair, until 256 coefficients
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
  // byte-serial (v5, compact): one stream byte per clock from a one-lane
  // buffer, three bytes -> two candidates. 1 byte / clock instead of 3, still
  // faster than the sponge delivers a squeezed block (one permutation per
  // 168 bytes); replaces a 128-bit stream buffer with 24-bit shifts and a
  // 9-way lane insert
  reg  [63:0] lane;    // the lane being consumed, next byte in [7:0]
  reg   [3:0] lb;      // bytes left in lane (0..8)
  reg  [15:0] win;     // up to two earlier bytes of the current triple: b0 = [7:0], b1 = [15:8]
  reg   [1:0] wc;      // bytes in win (0..2)
  reg   [8:0] n;       // coefficients accepted
  reg  [11:0] pend;    // an accepted coefficient waiting for its partner
  reg         pv;
  reg   [6:0] widx;    // next word to write
  reg         fin;
  reg   [3:0] sl;

  wire        cons = !fin && (lb != 4'd0);            // a byte is consumed this clock
  wire  [7:0] nb   = lane[7:0];
  // a lane is taken when the buffer is empty or its last byte goes this clock
  assign in_ready  = !fin && ((lb == 4'd0) || (lb == 4'd1));
  wire        take = in_valid && in_ready;

  // the third byte of a triple completes it: b0 b1 = win, b2 = nb
  wire        can  = cons && (wc == 2'd2);
  wire [11:0] d1   = {win[11:8], win[7:0]};           // {b1[3:0], b0}
  wire [11:0] d2   = {nb, win[15:12]};                // {b2, b1[7:4]}
  wire        a1   = can && (d1 < 12'd3329);
  wire  [8:0] n1   = n + {8'd0, a1};
  wire        a2   = can && (d2 < 12'd3329) && (n1 < 9'd256);
  wire  [8:0] nn   = n1 + {8'd0, a2};

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
      lb   <= 4'd0;
      wc   <= 2'd0;
      n    <= 9'd0;
      pv   <= 1'b0;
      widx <= 7'd0;
      fin  <= 1'b0;
      lane <= 64'd0;
      win  <= 16'd0;
      if (start) sl <= slot;
    end else begin
      // lane buffer: load a new lane, or shift the consumed byte out
      if (take)      begin lane <= in_lane;                lb <= 4'd8; end
      else if (cons) begin lane <= {8'd0, lane[63:8]};     lb <= lb - 4'd1; end
      // the triple window
      if (cons) begin
        case (wc)
          2'd0:    begin win[7:0]  <= nb; wc <= 2'd1; end
          2'd1:    begin win[15:8] <= nb; wc <= 2'd2; end
          default: wc <= 2'd0;                        // triple complete (can)
        endcase
      end
      n <= nn;
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
