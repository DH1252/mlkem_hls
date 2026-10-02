// -----------------------------------------------------------------------------
// pqse_sample.v - unmasked sampler fed by the sponge's 16-bit word stream.
//
//   pqse_parse   SampleNTT (FIPS 203 Alg. 7): byte-serial, 3 bytes -> two 12-bit
//                candidates every 3 clocks, values < q kept, one word
//                {c[2w+1], c[2w]} written per accepted pair, until 256 coefficients
//
// Writes the polynomial RAM through one port: waddr = {slot, word}. Used for
// the public matrix entries. Every secret polynomial is sampled masked
// (SamplePolyCBD in pqse_masked.v), so there is no unmasked CBD sampler.
//
// UNTESTED FIRST VERSION - see hw/se/README.md.
// -----------------------------------------------------------------------------
module pqse_parse (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [3:0]  slot,
  input  wire        in_valid,
  input  wire [15:0] in_word,
  output wire        in_ready,
  output wire        done,
  output wire        we,
  output wire [10:0] waddr,
  output wire [23:0] wdata
);
  // byte-serial (v5, compact): one stream byte per clock from a one-word
  // buffer, three bytes -> two candidates. Faster than the sponge delivers a
  // squeezed block (one permutation per 168 bytes)
  reg  [15:0] lane;    // the word being consumed, next byte in [7:0]
  reg   [1:0] lb;      // bytes left in the word (0..2)
  reg  [15:0] win;     // up to two earlier bytes of the current triple: b0 = [7:0], b1 = [15:8]
  reg   [1:0] wc;      // bytes in win (0..2)
  reg   [8:0] n;       // coefficients accepted
  reg  [11:0] pend;    // an accepted coefficient waiting for its partner
  reg         pv;
  reg   [6:0] widx;    // next word to write
  reg         fin;
  reg   [3:0] sl;

  wire        cons = !fin && (lb != 2'd0);            // a byte is consumed this clock
  wire  [7:0] nb   = lane[7:0];
  // a word is taken when the buffer is empty or its last byte goes this clock
  assign in_ready  = !fin && ((lb == 2'd0) || (lb == 2'd1));
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
  assign waddr = wr ? {sl, widx} : 11'd0;           // 0 when not writing (OR-combined port, pqse_core.v)
  assign wdata = wr ? {v1, v0} : 24'd0;
  assign done  = fin;

  always @(posedge clk) begin
    if (rst || start) begin
      lb   <= 2'd0;
      wc   <= 2'd0;
      n    <= 9'd0;
      pv   <= 1'b0;
      widx <= 7'd0;
      fin  <= 1'b0;
      lane <= 16'd0;
      win  <= 16'd0;
      if (start) sl <= slot;
    end else begin
      // word buffer: load a new word, or shift the consumed byte out
      if (take)      begin lane <= in_word;                lb <= 2'd2; end
      else if (cons) begin lane <= {8'd0, lane[15:8]};     lb <= lb - 2'd1; end
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
