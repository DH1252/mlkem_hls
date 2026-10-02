// -----------------------------------------------------------------------------
// pqse_puf.v - PUF and fuzzy extractor of the PQSE secure element.
//
//   pqse_puf_raw  one response bit per request (bit idx of 960). Sources:
//                   PQSE_PUF_LATCH  SRAM-cell PUF: 960 cells, each the storage core
//                                   of an SRAM cell (two cross-coupled NAND gates,
//                                   pqse_pufcell). Rows are held excited (both nodes
//                                   of every cell high) except the one being read; on
//                                   release the
//                                   pair falls into 0/1 or 1/0 as the mismatch of
//                                   its two gates decides - the power-up of an SRAM
//                                   cell, repeatable at any time (so the majority
//                                   reads of the extractor work). Standard cells on
//                                   a chip (SKY130: 2 x nand2 per bit, ~0.01 mm2 for
//                                   the array), two LUTs per bit on an FPGA - the
//                                   way to get an SRAM-type PUF on Gowin parts,
//                                   whose block RAMs are zeroed by configuration.
//                                   Every cell is in exactly one response bit, so
//                                   the bits are independent.
//                   PQSE_PUF_BFLY   the same array and read schedule, but every cell
//                                   is a butterfly cell (pqse_bflycell): two
//                                   transparent latches in the logic cells'
//                                   flip-flops, cross-coupled through their D
//                                   inputs, one with an asynchronous clear, the
//                                   other with an asynchronous preset. Exciting
//                                   forces the pair to 0/1, which the loop cannot
//                                   hold; on release it falls to 0/0 or 1/1 as the
//                                   two paths' mismatch decides (Kumar et al.,
//                                   "The Butterfly PUF", HOST 2008). 2 latches and
//                                   no LUT per bit (the latch gates of a column on
//                                   one net, so synthesis cannot merge identical
//                                   cells): the array moves from ~1,920 LUTs to
//                                   ~1,920 of the FPGA's flip-flops.
//                                   Gowin latch primitives (DLC / DLP); implies
//                                   PQSE_PUF_LATCH (same row / read control).
//                   PQSE_PUF_SRAM  a dedicated SRAM macro (32 x 32) that nothing
//                                   writes: its power-up contents are the response
//                                   (one sample per power-up; repeated reads return
//                                   the same bits). pqse_puf_sram is a black box for
//                                   synthesis: map it to the PDK's SRAM.
//                   (default) simulation model: a fixed per-device bit pattern,
//                   ~1.6% of the bits flipped on every read (noise), a "drift"
//                   switch that permanently flips 9.4% of the bits (3 per 32-bit
//                   block), as a temperature / voltage change would, and a
//                   "noisy" switch (20% errors per read, a very noisy device)
//
//   pqse_puf      code-offset fuzzy extractor with the Reed-Muller code
//                 RM(1,5) = [32, 6, 16]: corrects up to 7 errors in every block
//                 of 32 response bits (22% bit-error rate). 30 blocks: 960
//                 response bits, 180-bit key, 960 bits of helper data.
//                   ENROLL  key k from a masked seed entry (TRNG). Each response
//                           bit is read 5 times (majority: a clean reference),
//                           helper w = r XOR C(k) -> buffer (public); k is written
//                           back in canonical form (180 bits, lanes 0..2) so the
//                           microcode can store its check value H(k || "C") (64
//                           bits) in the last helper lane
//                   RECON   one read per response bit (RECON3 / RECON5: the
//                           majority of 3 / 5 reads; the microcode retries with
//                           them when the check value does not match). The decoder works on
//                           y = r XOR w XOR C(R) = C(k XOR R) XOR e with a fresh
//                           random 6-bit R per block, so it decodes k XOR R and
//                           the key comes out as Boolean shares (k ^ R, R):
//                           the unmasked key never exists in the decoder.
//                           The 32 bits of a block are read in a random order
//                           (bit x ^ xm, xm fresh per block), so the read
//                           schedule does not line up across reconstructions.
//                           Decoding = maximum likelihood over the 64 codewords
//                           (Hamming distance, one bit per clock: 32 clocks per
//                           codeword pair, v5).
//                   RAW     960 single reads -> buffer (TEST only: measure the
//                           bit-error rate and uniformity, scripts/pqse_puf_stats.py)
//                 The KEK is SHA3-256 of the 180-bit key, computed by the masked sponge.
//
// Entropy: the code-offset construction leaks n - k = 26 bits per 32-bit block
// through the helper data. With independent response bits (one cell per bit) of
// min-entropy h each, the key keeps 30 * (32 h - 26) bits: 128 bits need
// h >= 0.946 (132 bits at h = 0.95). Measure h with PF_RAW on several devices
// (scripts/pqse_puf_stats.py) and raise PUF_NB if it is lower.
// -----------------------------------------------------------------------------
`ifdef PQSE_PUF_BFLY
`ifndef PQSE_PUF_LATCH
`define PQSE_PUF_LATCH          // the butterfly array uses the latch PUF's row control
`endif
`endif

module pqse_puf_raw #(
  parameter WIN    = 2048,      // (kept for the interface; the cell PUFs need no window)
  parameter SETTLE = 8          // clocks from releasing a row to sampling a cell
) (
  input  wire       clk,
  input  wire       rst,
  input  wire       req,
  input  wire [9:0] idx,
  output reg        done,
  output reg        rbit
);
`ifdef PQSE_PUF_LATCH
  // ---------------- SRAM-cell PUF: 30 rows x 32 cells ----------------
  // Every row is held excited except the one being read (v5): an excited cell
  // has a fixed output (NAND pair: q = 1; butterfly: q = a = 0), so the read
  // needs no 960-way multiplexer, only a per-column AND / OR across the 30
  // rows and a 32-way column select (~1/3 of the LUTs). Also, outside a read
  // no cell holds a resolved response bit.
  // Read: the row stays excited 2 more clocks, is released (rel), resolves for
  // SETTLE clocks while the synchronizer follows the cell, then is excited again.
  reg  [4:0]  rsel;             // the row being read
  reg  [4:0]  csel;             // the column being read
  reg         rel;              // row rsel released (out of excitation)
  reg  [3:0]  cnt;
  reg  [1:0]  ph;
  reg         s1, s2;           // synchronizer (a cell may still be resolving)
  wire [959:0] qv;
  wire [31:0]  colv;            // per column: the released row's cell (excited rows neutral)
`ifdef PQSE_PUF_BFLY
  // butterfly: the latch gates of a column (only the column being read is open)
  reg  [31:0]  pgate;
  always @(posedge clk) pgate <= 32'd1 << csel;
`endif
  genvar g, gc;
  generate
    for (g = 0; g < 30; g = g + 1) begin : g_row
      wire sel_row = rel && (rsel == g);
      // e = 0: excited (both nodes 1); e = 1: the pair resolves and holds
      wire e_row = sel_row;
`ifdef PQSE_PUF_BFLY
      // active-high excite, one net per row: the inversion stays in the row
      // decode, so the cells themselves need no LUT
      wire x_row = !sel_row;
`endif
      for (gc = 0; gc < 32; gc = gc + 1) begin : g_cell
`ifdef PQSE_PUF_BFLY
        pqse_bflycell u_c (.x(x_row), .g(pgate[gc]), .q(qv[32*g + gc]));
`else
        pqse_pufcell u_c (.e(e_row), .q(qv[32*g + gc]));
`endif
      end
    end
    for (gc = 0; gc < 32; gc = gc + 1) begin : g_colv
      wire [29:0] cb;
      for (g = 0; g < 30; g = g + 1) begin : g_cb
        assign cb[g] = qv[32*g + gc];
      end
`ifdef PQSE_PUF_BFLY
      assign colv[gc] = |cb;            // excited butterfly cells output 0
`else
      assign colv[gc] = &cb;            // excited NAND pairs output 1
`endif
    end
  endgenerate
  wire        cq   = colv[csel];   // the cell being read ("cell" is a Verilog-2001 keyword)

  always @(posedge clk) begin
    if (rst) begin
      rel <= 1'b0; ph <= 2'd0; done <= 1'b0; s1 <= 1'b0; s2 <= 1'b0;
    end else begin
      done <= 1'b0;
      s1   <= (ph == 2'd2) ? cq : 1'b0;          // sampled only while a read is settling
      s2   <= s1;
      case (ph)
        2'd0: if (req) begin
          rsel <= idx[9:5];
          csel <= idx[4:0];
          cnt  <= 4'd0;
          ph   <= 2'd1;
        end
        2'd1: begin                               // 2 more clocks excited, then release
          cnt <= cnt + 4'd1;
          if (cnt == 4'd1) begin rel <= 1'b1; cnt <= 4'd0; ph <= 2'd2; end
        end
        2'd2: begin                               // the row resolves; s1 / s2 follow the cell
          cnt <= cnt + 4'd1;
          if (cnt == SETTLE[3:0]) ph <= 2'd3;
        end
        default: begin                            // sample, excite the row again
          rbit <= s2; done <= 1'b1; rel <= 1'b0; ph <= 2'd0;
        end
      endcase
    end
  end
`elsif PQSE_PUF_SRAM
  // ---------------- SRAM PUF: power-up contents of a dedicated, never written SRAM ----------------
  wire [31:0] sw;
  reg  [4:0]  col;
  reg  [1:0]  ph;
  pqse_puf_sram u_sram (.clk(clk), .re(req && (ph == 2'd0)), .addr(idx[9:5]), .q(sw));
  always @(posedge clk) begin
    if (rst) begin
      ph <= 2'd0; done <= 1'b0;
    end else begin
      done <= 1'b0;
      case (ph)
        2'd0: if (req) begin col <= idx[4:0]; ph <= 2'd1; end
        2'd1: ph <= 2'd2;                         // the word arrives
        default: begin rbit <= sw[col]; done <= 1'b1; ph <= 2'd0; end
      endcase
    end
  end
`else
  // ---------------- simulation model ----------------
  reg [15:0] lfsr;
  reg [31:0] nz;                // noisy mode: xorshift32, one step per read
  reg [15:0] cnt;
  reg        busy_;
  reg [9:0]  ix;
  reg        drift = 1'b0;      // testbench: set to emulate a temperature change
  reg        noisy = 1'b0;      // testbench: 20% bit errors per read (a very noisy
                                // device: one read per bit no longer decodes, the
                                // majority of 3 or 5 reads does)
  function f(input [9:0] i);              // the "device" pattern
    reg [31:0] h;
    begin
      h = {22'd0, i} * 32'h9E3779B1 + 32'h5EED1234;
      f = ^h[31:24];
    end
  endfunction
  // drift: 3 of every 32 bits (9.4%) flip for good - a repetition / majority
  // scheme cannot repair that (every read agrees on the wrong value), the
  // RM(1,5) code corrects up to 7 errors per 32-bit block
  function dr(input [9:0] i);
    dr = (i[4:0] == 5'd3) || (i[4:0] == 5'd17) || (i[4:0] == 5'd29);
  endfunction
  wire [31:0] nz1 = nz  ^ (nz  << 13);
  wire [31:0] nz2 = nz1 ^ (nz1 >> 17);
  wire [31:0] nzn = nz2 ^ (nz2 << 5);
  wire        ne  = noisy ? (nzn[31:24] < 8'd51)       // 51 / 256 = 19.9% per read
                          : (lfsr[5:0] == 6'd0);        // 1 / 64 = 1.6% per read
  always @(posedge clk) begin
    if (rst) begin
      lfsr <= 16'hACE1; nz <= 32'h2545F491; busy_ <= 1'b0; done <= 1'b0;
    end else begin
      done <= 1'b0;
      lfsr <= {lfsr[14:0], lfsr[15] ^ lfsr[13] ^ lfsr[12] ^ lfsr[10]};
      if (req && !busy_) begin busy_ <= 1'b1; cnt <= 16'd0; ix <= idx; end
      else if (busy_) begin
        cnt <= cnt + 16'd1;
        if (cnt == 16'd3) begin
          busy_ <= 1'b0;
          done  <= 1'b1;
          nz    <= nzn;
          rbit  <= f(ix) ^ (drift & dr(ix)) ^ ne;
        end
      end
    end
  end
`endif
endmodule


`ifdef PQSE_PUF_LATCH
// one SRAM-cell PUF bit: two cross-coupled NAND gates (the storage core of an
// SRAM cell). e = 0: both outputs 1 (excited); e = 1: the pair is bistable and
// settles to q = 0 or 1 as the two gates' mismatch decides, then holds it.
// Place the two gates next to each other, with identical routing (chip: a
// symmetric pair of cells; FPGA: both LUTs in one logic cell / slice).
(* keep_hierarchy *)   // never flattened: synthesis must not restructure the pair
module pqse_pufcell (
  input  wire e,
  output wire q
);
`ifdef PQSE_ASIC_SKY130
  wire qb;
  sky130_fd_sc_hd__nand2_1 u_a (.A(e), .B(qb), .Y(q));
  sky130_fd_sc_hd__nand2_1 u_b (.A(e), .B(q),  .Y(qb));
`else
  // keep: Yosys / Quartus; syn_keep: GowinSynthesis
  (* keep = 1 *) wire n_a /* synthesis syn_keep = 1 */;
  (* keep = 1 *) wire n_b /* synthesis syn_keep = 1 */;
  assign n_a = ~(e & n_b);
  assign n_b = ~(e & n_a);
  assign q   = n_a;
`endif
endmodule

`ifdef PQSE_PUF_BFLY
// one butterfly PUF bit: two latches (open while the column gate g is 1), each one's D
// fed by the other's Q, built from the logic cells' flip-flops in latch mode.
// x = 1: latch a cleared, latch b preset (a = 0, b = 1: a state the loop of
// two non-inverting stages cannot hold); x = 0: the pair falls to a = b = 0 or
// a = b = 1 as the mismatch of the two D paths decides, then holds it.
// No LUT: the cell is two flip-flops and two routes. Place a and b in one
// logic cell (CLS), or in two neighbouring ones if a CLS cannot mix a clear and
// a preset register, with matched D routes; keep the x fan-out of a row on one
// net. (Xilinx: LDCE / LDPE, as in the original butterfly PUF.)
// Unique inputs per cell: with only the row's excite net, all 32 cells of a
// row are logically identical and GowinSynthesis merged them as equivalent
// registers (990 latches instead of 1,920). v4 gave each cell its own excite
// flip-flop (960 flip-flops); v5 instead drives the two latch gates of a cell
// from its column's gate net g: a cell's inputs (row x, column g) are unique,
// and it costs 32 gate nets instead of 960 flip-flops. Both latches still
// leave excitation together on the row net x (the butterfly's symmetry); g is
// set one read ahead (pqse_puf_raw), while the cell is still excited:
//   row excited (x = 1)            a = 0, b = 1 whatever g: q = 0
//   row released, g = 0 (closed)   both latches hold the excited state: q = 0
//   row released, g = 1 (open)     the butterfly resolves: q = response
// so the per-column OR still sees only the cell being read.
// GowinSynthesis also gets syn_preserve on the module and the latches and
// syn_dont_touch on the two nodes (its attribute against merging equivalent
// registers).
(* keep_hierarchy *)   // never flattened: synthesis must not restructure the pair
module pqse_bflycell (
  input  wire x,
  input  wire g,
  output wire q
) /* synthesis syn_preserve = 1 */;
  (* keep = 1 *) wire q_a /* synthesis syn_dont_touch = 1 */;
  (* keep = 1 *) wire q_b /* synthesis syn_dont_touch = 1 */;
`ifdef PQSE_GOWIN_EDA
  // Gowin EDA (GowinSynthesis, UG288): the latch gate pin is G
  DLC #(.INIT(1'b0)) u_a (.D(q_b), .G(g), .CLEAR(x),  .Q(q_a)) /* synthesis syn_preserve = 1 */;
  DLP #(.INIT(1'b1)) u_b (.D(q_a), .G(g), .PRESET(x), .Q(q_b)) /* synthesis syn_preserve = 1 */;
`else
  // Yosys / nextpnr cell library: the latch gate pin is CLK
  (* keep = 1 *) DLC #(.INIT(1'b0)) u_a (.D(q_b), .CLK(g), .CLEAR(x),  .Q(q_a));
  (* keep = 1 *) DLP #(.INIT(1'b1)) u_b (.D(q_a), .CLK(g), .PRESET(x), .Q(q_b));
`endif
  assign q = q_a;
endmodule
`endif
`endif

`ifdef PQSE_PUF_SRAM
// the SRAM-PUF array: 32 words x 32 bits, never written. For synthesis it is a
// black box: replace it with the PDK's SRAM macro (read port only connected,
// write enable tied off). The simulation body gives every word a fixed
// "device" pattern with a few bits that differ at each power-up.
`ifdef SYNTHESIS
(* blackbox *)
module pqse_puf_sram (
  input  wire        clk,
  input  wire        re,
  input  wire [4:0]  addr,
  output wire [31:0] q
);
endmodule
`else
module pqse_puf_sram (
  input  wire        clk,
  input  wire        re,
  input  wire [4:0]  addr,
  output reg  [31:0] q
);
  reg [31:0] mem [0:31];
  integer i;
  reg [31:0] h, n;
  initial begin
    n = 32'h1234_5678 ^ $random;                  // power-up noise of this simulation run
    for (i = 0; i < 32; i = i + 1) begin
      h      = i * 32'h9E3779B1 + 32'h5EED1234;
      h      = h ^ (h >> 15);
      h      = h * 32'h2C1B3C6D;
      n      = n ^ (n << 13); n = n ^ (n >> 17); n = n ^ (n << 5);
      // the device pattern, ~3% of its bits flipped (this power-up's noise)
      mem[i] = (h ^ (h >> 12)) ^ (n & (n >> 3) & (n >> 7) & (n >> 11) & (n >> 19));
    end
  end
  always @(posedge clk) if (re) q <= mem[addr];
endmodule
`endif
`endif


module pqse_puf #(
  parameter WIN = 2048
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [95:0] ins,       // [91:88] op, [87:84] entry, [83:75] buffer lane (helper / raw)
  output wire        busy,
  // I/O buffer
  output reg         bre,
  output reg  [10:0] braddr,
  input  wire [15:0] brdata,
  output reg         bwe,
  output reg  [10:0] bwaddr,
  output reg  [15:0] bwdata,
  // seed registers
  output reg         sre,
  output reg  [7:0]  sraddr,
  input  wire [15:0] srd0,
  input  wire [15:0] srd1,
  output reg         swe,
  output reg  [7:0]  swaddr,
  output reg  [15:0] swd0,
  output reg  [15:0] swd1,
  // randomness
  input  wire [63:0] rnd,
  output reg         rnd_take
);
  `include "pqse_defs.vh"

  // v5 (serial core): the decoder adds one bit per clock instead of a 32-bit
  // popcount, and the key never sits in the extractor as a whole: the seed
  // registers (16-bit words, entry ent, words 0..11 = lanes 0..2) hold it.
  //   enroll       K0 / K1 (one 16-bit word per share) shift the key bits out,
  //                6 per block into kb0 / kb1 (the block's key bits), a new
  //                seed word read whenever K runs empty; the canonical form
  //                (180 bits, the rest 0) is then made in place: word 11 &= 0xF
  //                (per share), words 12..15 := 0
  //   reconstruct  the decoded k ^ R and R of each block enter K0 / K1 at the
  //                top, one bit per clock; every 16 bits are one seed word
  //                (written, K cleared), the last 4 bits padded with zeros,
  //                then words 12..15 := 0
  localparam [4:0] U_IDLE = 5'd0,  U_KRQ = 5'd1,  U_KRD = 5'd2,  U_BLK  = 5'd3,
                   U_HLD  = 5'd4,  U_MSK = 5'd5,  U_REQ = 5'd6,  U_WAIT = 5'd7,
                   U_DEC  = 5'd8,  U_INS = 5'd9,  U_HB  = 5'd10, U_EKB  = 5'd11,
                   U_HWR  = 5'd12, U_RWR = 5'd13, U_FIN = 5'd14, U_KWR  = 5'd15,
                   U_EFN  = 5'd16, U_EF2 = 5'd17;

  reg  [4:0]   st;
  reg          idl;          // the idle registers are cleared
  reg  [1:0]   mode;         // 0 enroll, 1 reconstruct, 2 raw
  reg  [2:0]   nrd;          // reconstruct: reads per response bit (1, 3 or 5, majority)
  reg  [3:0]   ent;
  reg  [10:0]  hb;           // helper / raw base word (lane * 4)
  reg  [15:0]  K0, K1;       // key word shift registers, per share
  reg  [4:0]   kn;           // enroll: bits left in K; reconstruct: bits in K (0..16)
  reg  [5:0]   kb0, kb1;     // enroll: this block's 6 key bits, per share
  reg  [4:0]   kret;         // U_KWR returns here
  reg  [4:0]   blk;          // block 0..29
  reg  [4:0]   x;            // bit within the block
  reg  [9:0]   b;            // response bit (raw mode)
  reg  [2:0]   rv, ones;     // majority voting
  reg  [15:0]  hl;           // helper word in / out, raw word
  reg  [31:0]  wm;           // helper bits w of the block (reconstruct)
  reg          wb;           // reconstruct: w[xr] ^ C(R)[xr], registered before the
                             // response bit meets it (r ^ w alone would be C(k) ^ e)
  reg  [31:0]  y;            // y = r XOR w XOR C(R)
  reg  [5:0]   R;            // block mask
  reg  [4:0]   xm;           // reconstruct: read order of the block, bit x ^ xm (random per block)
  reg  [4:0]   u;            // decoder: codeword pair
  reg  [4:0]   bi;           // decoder: bit of the codeword
  reg  [5:0]   acc;          // decoder: distance so far
  reg  [5:0]   best;
  reg  [5:0]   bm;           // best message
  reg  [3:0]   kc;           // seed word counter
  reg  [2:0]   sc;           // key bit counter of the block (0..5)

  wire raw_done, raw_bit;
  reg  raw_req;
  // the response bit being read: in order for enroll and raw dumps, in the
  // random order x ^ xm within each block for reconstruction (hiding: the
  // response bits themselves are read unmasked, as from any PUF)
  wire [4:0] xr   = x ^ xm;
  wire [9:0] ridx = (mode == 2'd2) ? b : {blk, xr};
  pqse_puf_raw #(.WIN(WIN)) u_raw (.clk(clk), .rst(rst), .req(raw_req), .idx(ridx),
                                  .done(raw_done), .rbit(raw_bit));

  assign busy = start | (st != U_IDLE);

  // RM(1,5) codeword bit x of message m (m[0]: all-ones row, m[5:1]: x's bits)
  function cw(input [5:0] m, input [4:0] xx);
    cw = m[0] ^ (^(m[5:1] & xx));
  endfunction

  // enrollment: majority of 5 reads; reconstruction: majority of nrd (1, 3, 5)
  wire [2:0] ones_n = ones + {2'b00, raw_bit};
  wire       maj    = (ones_n >= 3'd3);
  wire       rmaj   = ({ones_n, 1'b0} > {1'b0, nrd});
  // helper bit w = r ^ C(k0) ^ C(k1), in two clocks: hp = r ^ C(k0) is
  // registered first (masked by C(k1)), so no gate sees C(k0) ^ C(k1) = C(k)
  reg        hp;

  // decoder, one bit per clock: distance of y to the codeword (u, 0); the
  // pair's other word (u, 1) is at 32 - distance. y rotates once per codeword.
  wire [5:0] acc_n  = acc + {5'd0, y[0] ^ cw({u, 1'b0}, bi)};
  wire [5:0] dinv   = 6'd32 - acc_n;
  wire       use1   = (dinv < acc_n);
  wire [5:0] cand   = use1 ? dinv : acc_n;

  // helper words of block blk: 2 blk (bits 0..15), 2 blk + 1 (bits 16..31)
  wire [10:0] hwa   = hb + {5'd0, blk, 1'b0};

  always @* begin
    bre = 1'b0; braddr = 11'd0; bwe = 1'b0; bwaddr = 11'd0; bwdata = 16'd0;
    sre = 1'b0; sraddr = 8'd0; swe = 1'b0; swaddr = 8'd0;
    // write-back data: the key word shift registers (each bus one share; the
    // core uses it only while this unit writes; K is 0 while idle)
    swd0 = K0; swd1 = K1;
    rnd_take = 1'b0; raw_req = 1'b0;
    case (st)
      U_KRQ: begin sre = 1'b1; sraddr = {ent, kc}; end
      U_BLK: begin bre = 1'b1; braddr = hwa; end                  // helper bits 0..15
      U_HLD: begin bre = 1'b1; braddr = hwa + 11'd1; end          // helper bits 16..31
      U_MSK: rnd_take = 1'b1;
      U_REQ: raw_req = 1'b1;
      // enroll: x was just advanced past bit 15 (x = 16) or 31 (x = 0)
      U_HWR: begin bwe = 1'b1; bwaddr = hwa + {10'd0, ~x[4]}; bwdata = hl; end
      U_RWR: begin bwe = 1'b1; bwaddr = hb + {5'd0, b[9:4]} - 11'd1; bwdata = hl; end
      U_KWR: begin swe = 1'b1; swaddr = {ent, kc}; end
      // enroll, canonical form: word 11 keeps only key bits 176..179 (bits 3:0)
      U_EFN: begin sre = 1'b1; sraddr = {ent, 4'd11}; end
      U_EF2: begin
        swe = 1'b1; swaddr = {ent, 4'd11};
        swd0 = srd0 & 16'h000F; swd1 = srd1 & 16'h000F;
      end
      default: ;
    endcase
  end

  always @(posedge clk) begin
    if (rst) begin
      st  <= U_IDLE;
      idl <= 1'b0;
    end else begin
      case (st)
        U_IDLE: if (!start) begin
          // idle: no key material left in the extractor's registers (cleared
          // once on entering idle, then held: low power, a gateable clock)
          if (!idl) begin
            K0 <= 16'd0; K1 <= 16'd0; kb0 <= 6'd0; kb1 <= 6'd0;
            y <= 32'd0; wm <= 32'd0; hp <= 1'b0; wb <= 1'b0;
            R <= 6'd0; xm <= 5'd0; bm <= 6'd0;
            idl <= 1'b1;
          end
        end else begin
          idl  <= 1'b0;
          mode <= (ins[91:88] == PF_ENROLL) ? 2'd0 : (ins[91:88] == PF_RAW) ? 2'd2 : 2'd1;
          nrd  <= (ins[91:88] == PF_RECON5) ? 3'd5 : (ins[91:88] == PF_RECON3) ? 3'd3 : 3'd1;
          ent  <= ins[87:84];
          hb   <= {ins[83:75], 2'b00};
          blk  <= 5'd0;
          x    <= 5'd0;
          xm   <= 5'd0;                                   // enroll / raw: in order
          b    <= 10'd0;
          rv   <= 3'd0;
          ones <= 3'd0;
          kc   <= 4'd0;
          kn   <= 5'd0;
          sc   <= 3'd0;
          K0   <= 16'd0;
          K1   <= 16'd0;
          st   <= (ins[91:88] == PF_ENROLL) ? U_EKB : (ins[91:88] == PF_RAW) ? U_REQ : U_BLK;
        end
        // ---- enroll: the block's 6 key bits into kb0 / kb1, one per clock, a
        // new seed word into K0 / K1 when they are empty ----
        U_EKB: begin
          if (kn == 5'd0) begin
            st <= U_KRQ;
          end else begin
            kb0 <= {K0[0], kb0[5:1]}; K0 <= {1'b0, K0[15:1]};
            kb1 <= {K1[0], kb1[5:1]}; K1 <= {1'b0, K1[15:1]};
            kn  <= kn - 5'd1;
            sc  <= sc + 3'd1;
            if (sc == 3'd5) begin sc <= 3'd0; st <= U_REQ; end
          end
        end
        U_KRQ: st <= U_KRD;                               // seed word kc read issued
        U_KRD: begin                                      // ... arrives
          K0 <= srd0; K1 <= srd1; kn <= 5'd16;
          kc <= kc + 4'd1;
          st <= U_EKB;
        end
        // ---- reconstruct: start of a block, its two helper words ----
        U_BLK: st <= U_HLD;                               // word 2 blk read issued
        U_HLD: begin hl <= brdata; st <= U_MSK; end       // ... arrives; word 2 blk + 1 read issued
        U_MSK: begin                                      // ... arrives (brdata)
          R  <= rnd[5:0];
          xm <= rnd[10:6];
          wm <= {brdata, hl};
          x  <= 5'd0;
          st <= U_REQ;
        end
        U_REQ: begin
          wb <= wm[xr] ^ cw(R, xr);                       // masked helper bit of this read
          st <= U_WAIT;
        end
        U_WAIT: if (raw_done) begin
          case (mode)
            2'd0: begin                                   // enroll: 5 reads per bit
              if (rv != 3'd4) begin
                ones <= ones_n; rv <= rv + 3'd1; st <= U_REQ;
              end else begin
                ones <= 3'd0; rv <= 3'd0;
                hp   <= maj ^ cw(kb0, x);                 // r ^ C(k0)
                st   <= U_HB;
              end
            end
            2'd1: begin                                   // reconstruct: majority of nrd reads
              if ({1'b0, rv} != {1'b0, nrd} - 4'd1) begin
                ones <= ones_n; rv <= rv + 3'd1; st <= U_REQ;
              end else begin
                ones <= 3'd0; rv <= 3'd0;
                y[xr] <= rmaj ^ wb;                       // bit xr of y = r' ^ (w ^ C(R))
                x <= x + 5'd1;
                if (x == 5'd31) begin
                  u <= 5'd0; bi <= 5'd0; acc <= 6'd0; best <= 6'd63; st <= U_DEC;
                end else st <= U_REQ;
              end
            end
            default: begin                                // raw dump
              hl <= {raw_bit, hl[15:1]};
              b  <= b + 10'd1;
              st <= (b[3:0] == 4'd15) ? U_RWR : U_REQ;
            end
          endcase
        end
        // ---- decoder: one bit per clock, 32 clocks per codeword pair ----
        U_DEC: begin
          y  <= {y[0], y[31:1]};                          // 32 rotations: y is back
          bi <= bi + 5'd1;
          if (bi == 5'd31) begin
            acc <= 6'd0;
            if (cand < best) begin
              best <= cand;
              bm   <= {u, use1};
            end
            u <= u + 5'd1;
            if (u == 5'd31) begin sc <= 3'd0; st <= U_INS; end
          end else begin
            acc <= acc_n;
          end
        end
        // decoded k ^ R and R enter K0 / K1 at the top, LSB first (6 clocks);
        // a full word is written first (U_KWR)
        U_INS: begin
          if (kn == 5'd16) begin
            kret <= U_INS;
            st   <= U_KWR;
          end else begin
            K0 <= {bm[0], K0[15:1]}; bm <= {1'b0, bm[5:1]};
            K1 <= {R[0],  K1[15:1]}; R  <= {1'b0, R[5:1]};
            kn <= kn + 5'd1;
            sc <= sc + 3'd1;
            if (sc == 3'd5) begin
              sc <= 3'd0;
              if (blk == PUF_NB - 1) st <= U_FIN;
              else begin blk <= blk + 5'd1; st <= U_BLK; end
            end
          end
        end
        U_HB: begin                                       // + C(k1): the public helper bit
          hl <= {hp ^ cw(kb1, x), hl[15:1]};
          x  <= x + 5'd1;
          st <= (x[3:0] == 4'd15) ? U_HWR : U_REQ;       // 16 bits: one helper word
        end
        U_HWR: begin                                      // helper word written this clock
          if (x == 5'd0) begin                            // the block's second word
            if (blk == PUF_NB - 1) st <= U_EFN;
            else begin blk <= blk + 5'd1; st <= U_EKB; end
          end else st <= U_REQ;
        end
        U_RWR: st <= (b == PUF_NR) ? U_IDLE : U_REQ;
        // ---- enroll, canonical form in place: word 11 &= 0xF, then words 12..15 = 0
        // (the 12 unused bits left in K are dropped) ----
        U_EFN: begin                                      // word 11 read issued
          K0 <= 16'd0; K1 <= 16'd0; kn <= 5'd0;
          kb0 <= 6'd0; kb1 <= 6'd0;
          st <= U_EF2;
        end
        U_EF2: begin kc <= 4'd12; st <= U_FIN; end        // word 11 written this clock
        // ---- the last key word padded with zeros, then zero words up to 15 ----
        U_FIN: begin
          if (kn == 5'd16 || kn == 5'd0) begin            // a full (or a zero) word to write
            kret <= U_FIN;
            st   <= U_KWR;
          end else begin
            K0 <= {1'b0, K0[15:1]};
            K1 <= {1'b0, K1[15:1]};
            kn <= kn + 5'd1;
          end
        end
        // ---- write word kc = K this clock, then clear K ----
        U_KWR: begin
          K0 <= 16'd0; K1 <= 16'd0; kn <= 5'd0;
          kc <= kc + 4'd1;
          st <= (kc == 4'd15) ? U_IDLE : kret;
        end
        default: st <= U_IDLE;
      endcase
    end
  end

`ifdef PQSE_TRACE
  always @(posedge clk) begin
    if (st == U_KWR)
      $display("[%0t] PUF %s: key word %0d = %h (simulation only)", $time,
               (mode == 2'd0) ? "enroll" : "reconstruct", kc, K0 ^ K1);
  end
`endif
endmodule
