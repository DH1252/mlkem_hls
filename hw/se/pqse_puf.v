// -----------------------------------------------------------------------------
// pqse_puf.v - PUF and fuzzy extractor of the PQSE secure element.
//
//   pqse_puf_raw  one response bit per request (bit idx of 960). Sources:
//                   PQSE_PUF_LATCH  SRAM-cell PUF: 960 cells, each the storage core
//                                   of an SRAM cell (two cross-coupled NAND gates,
//                                   pqse_pufcell). Exciting a row of 32 cells forces
//                                   both nodes of every cell high; on release the
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
//                                   "The Butterfly PUF", HOST 2008). 2 flip-flops
//                                   and no LUT per bit: the array moves from
//                                   ~1,920 LUTs to ~1,920 of the FPGA's flip-flops.
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
//                           (Hamming distance, one codeword pair per clock).
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
  // ---------------- SRAM-cell PUF: 30 rows x 32 cross-coupled NAND pairs ----------------
  reg  [4:0]  rsel;             // the row being excited / read
  reg  [9:0]  ix;
  reg         exc;              // excite: both nodes of every cell in row rsel high
  reg  [3:0]  cnt;
  reg  [1:0]  ph;
  reg         s1, s2;           // synchronizer (a cell may still be resolving)
  wire [959:0] qv;
  genvar g, gc;
  generate
    for (g = 0; g < 30; g = g + 1) begin : g_row
      // e = 0: excited (both nodes 1); e = 1: the pair holds what it resolved to
      wire e_row = !(exc && (rsel == g));
`ifdef PQSE_PUF_BFLY
      // active-high excite, one net per row: the inversion stays in the row
      // decode, so the cells themselves need no LUT
      wire x_row = exc && (rsel == g);
`endif
      for (gc = 0; gc < 32; gc = gc + 1) begin : g_cell
`ifdef PQSE_PUF_BFLY
        pqse_bflycell u_c (.x(x_row), .q(qv[32*g + gc]));
`else
        pqse_pufcell u_c (.e(e_row), .q(qv[32*g + gc]));
`endif
      end
    end
  endgenerate
  wire        cq   = qv[ix];       // the cell being read ("cell" is a Verilog-2001 keyword)

  always @(posedge clk) begin
    if (rst) begin
      exc <= 1'b0; ph <= 2'd0; done <= 1'b0; s1 <= 1'b0; s2 <= 1'b0;
    end else begin
      done <= 1'b0;
      s1   <= (ph == 2'd2) ? cq : 1'b0;          // sampled only while a read is settling
      s2   <= s1;
      case (ph)
        2'd0: if (req) begin
          ix   <= idx;
          rsel <= idx[9:5];
          exc  <= 1'b1;
          cnt  <= 4'd0;
          ph   <= 2'd1;
        end
        2'd1: begin                               // excite for 2 clocks, then release
          cnt <= cnt + 4'd1;
          if (cnt == 4'd1) begin exc <= 1'b0; cnt <= 4'd0; ph <= 2'd2; end
        end
        2'd2: begin                               // the row resolves; s1 / s2 follow the cell
          cnt <= cnt + 4'd1;
          if (cnt == SETTLE[3:0]) ph <= 2'd3;
        end
        default: begin rbit <= s2; done <= 1'b1; ph <= 2'd0; end
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
// one butterfly PUF bit: two always-transparent latches (G = 1), each one's D
// fed by the other's Q, built from the logic cells' flip-flops in latch mode.
// x = 1: latch a cleared, latch b preset (a = 0, b = 1: a state the loop of
// two non-inverting stages cannot hold); x = 0: the pair falls to a = b = 0 or
// a = b = 1 as the mismatch of the two D paths decides, then holds it.
// No LUT: the cell is two flip-flops and two routes. Place a and b in one
// logic cell (CLS), or in two neighbouring ones if a CLS cannot mix a clear and
// a preset register, with matched D routes; keep the x fan-out of a row on one
// net. (Xilinx: LDCE / LDPE, as in the original butterfly PUF.)
(* keep_hierarchy *)   // never flattened: synthesis must not restructure the pair
// All cells of a row see the same excite and are logically identical, so a
// synthesis tool may merge them as equivalent registers (GowinSynthesis kept
// one latch b per row): every cell is a separate physical source and must stay.
// GowinSynthesis: syn_preserve on the module and the latches, syn_dont_touch on
// the two nodes (its attribute against merging equivalent registers).
module pqse_bflycell (
  input  wire x,
  output wire q
) /* synthesis syn_preserve = 1 */;
  (* keep = 1 *) wire q_a /* synthesis syn_dont_touch = 1 */;
  (* keep = 1 *) wire q_b /* synthesis syn_dont_touch = 1 */;
`ifdef PQSE_GOWIN_EDA
  // Gowin EDA (GowinSynthesis, UG288): the latch gate pin is G
  DLC #(.INIT(1'b0)) u_a (.D(q_b), .G(1'b1), .CLEAR(x),  .Q(q_a)) /* synthesis syn_preserve = 1 */;
  DLP #(.INIT(1'b1)) u_b (.D(q_a), .G(1'b1), .PRESET(x), .Q(q_b)) /* synthesis syn_preserve = 1 */;
`else
  // Yosys / nextpnr cell library: the latch gate pin is CLK
  (* keep = 1 *) DLC #(.INIT(1'b0)) u_a (.D(q_b), .CLK(1'b1), .CLEAR(x),  .Q(q_a));
  (* keep = 1 *) DLP #(.INIT(1'b1)) u_b (.D(q_a), .CLK(1'b1), .PRESET(x), .Q(q_b));
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
  output reg  [8:0]  braddr,
  input  wire [63:0] brdata,
  output reg         bwe,
  output reg  [8:0]  bwaddr,
  output reg  [63:0] bwdata,
  // seed registers
  output reg         sre,
  output reg  [5:0]  sraddr,
  input  wire [63:0] srd0,
  input  wire [63:0] srd1,
  output reg         swe,
  output reg  [5:0]  swaddr,
  output reg  [63:0] swd0,
  output reg  [63:0] swd1,
  // randomness
  input  wire [63:0] rnd,
  output reg         rnd_take
);
  `include "pqse_defs.vh"

  localparam [3:0] U_IDLE = 4'd0, U_KRD = 4'd1, U_BLK = 4'd2, U_HLD = 4'd3, U_MSK = 4'd4,
                   U_REQ  = 4'd5, U_WAIT = 4'd6, U_DEC = 4'd7, U_HWR = 4'd8, U_RWR = 4'd9,
                   U_KWR  = 4'd10,
                   U_HB   = 4'd11;   // enroll: second half of the helper bit (share 1)

  reg  [3:0]   st;
  reg  [1:0]   mode;         // 0 enroll, 1 reconstruct, 2 raw
  reg  [2:0]   nrd;          // reconstruct: reads per response bit (1, 3 or 5, majority)
  reg  [3:0]   ent;
  reg  [8:0]   hb;           // helper / raw base lane
  reg  [191:0] K0, K1;       // key shares (180 bits used)
  reg  [4:0]   blk;          // block 0..29
  reg  [4:0]   x;            // bit within the block
  reg  [9:0]   b;            // response bit (raw mode)
  reg  [2:0]   rv, ones;     // majority voting (enroll)
  reg  [63:0]  hl;           // helper lane in / out, raw lane
  reg  [31:0]  wm;           // w XOR C(R) for the block (reconstruct)
  reg  [31:0]  y;            // y = r XOR w XOR C(R)
  reg  [5:0]  R;            // block mask
  reg  [4:0]  xm;           // reconstruct: read order of the block, bit x ^ xm (random per block)
  reg  [4:0]   u;            // decoder: codeword index
  reg  [5:0]   best;
  reg  [5:0]   bm;           // best message
  reg  [2:0]   kc;           // seed lane counter

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
  function [31:0] cwv(input [5:0] m);
    integer i;
    begin
      for (i = 0; i < 32; i = i + 1) cwv[i] = cw(m, i[4:0]);
    end
  endfunction
  function [5:0] pop32(input [31:0] v);
    integer i;
    begin
      pop32 = 6'd0;
      for (i = 0; i < 32; i = i + 1) pop32 = pop32 + {5'd0, v[i]};
    end
  endfunction

  // enrollment: majority of 5 reads; reconstruction: majority of nrd (1, 3, 5)
  wire [2:0] ones_n = ones + {2'b00, raw_bit};
  wire       maj    = (ones_n >= 3'd3);
  wire       rmaj   = ({ones_n, 1'b0} > {1'b0, nrd});
  // key shares, block by block without 30-way indexing: the current block's 6
  // bits are always K[5:0]; after a block the registers shift right by 6
  // (enroll: rotate; reconstruct: the decoded block enters at the top). After
  // the 30 blocks the canonical 180-bit key is K[191:12] in both modes.
  wire [5:0] k0b    = K0[5:0];
  wire [5:0] k1b    = K1[5:0];
  // helper bit w = r ^ C(k0) ^ C(k1), in two clocks: hp = r ^ C(k0) is
  // registered first (masked by C(k1)), so no gate sees C(k0) ^ C(k1) = C(k)
  reg        hp;

  // decoder: distance to the codeword pair (u, 0) / (u, 1)
  // ("dist" is a SystemVerilog keyword, hence hdist)
  wire [5:0] hdist  = pop32(y ^ cwv({u, 1'b0}));
  wire [5:0] dinv   = 6'd32 - hdist;
  wire       use1   = (dinv < hdist);
  wire [5:0] cand   = use1 ? dinv : hdist;

  always @* begin
    bre = 1'b0; braddr = 9'd0; bwe = 1'b0; bwaddr = 9'd0; bwdata = 64'd0;
    sre = 1'b0; sraddr = 6'd0; swe = 1'b0; swaddr = 6'd0; swd0 = 64'd0; swd1 = 64'd0;
    rnd_take = 1'b0; raw_req = 1'b0;
    case (st)
      U_KRD: if (kc < 3'd3) begin sre = 1'b1; sraddr = {ent, kc[1:0]}; end
      U_BLK: if (mode == 2'd1 && !blk[0]) begin bre = 1'b1; braddr = hb + {4'd0, blk[4:1]}; end
      U_MSK: rnd_take = 1'b1;
      U_REQ: raw_req = 1'b1;
      U_HWR: begin bwe = 1'b1; bwaddr = hb + {4'd0, blk[4:1]}; bwdata = hl; end
      U_RWR: begin bwe = 1'b1; bwaddr = hb + {3'd0, b[9:6]} - 9'd1; bwdata = hl; end
      U_KWR: begin
        swe    = 1'b1;
        swaddr = {ent, kc[1:0]};
        case (kc)
          3'd0: begin swd0 = K0[75:12];            swd1 = K1[75:12];            end
          3'd1: begin swd0 = K0[139:76];           swd1 = K1[139:76];           end
          3'd2: begin swd0 = {12'd0, K0[191:140]}; swd1 = {12'd0, K1[191:140]}; end
          default: ;                                   // lane 3 = 0
        endcase
      end
      default: ;
    endcase
  end

  always @(posedge clk) begin
    if (rst) begin
      st <= U_IDLE;
    end else begin
      case (st)
        U_IDLE: if (!start) begin
          // idle: no key material left in the extractor's registers
          K0 <= 192'd0; K1 <= 192'd0; y <= 32'd0; wm <= 32'd0; hp <= 1'b0;
          R <= 6'd0; xm <= 5'd0; bm <= 6'd0;
        end else begin
          mode <= (ins[91:88] == PF_ENROLL) ? 2'd0 : (ins[91:88] == PF_RAW) ? 2'd2 : 2'd1;
          nrd  <= (ins[91:88] == PF_RECON5) ? 3'd5 : (ins[91:88] == PF_RECON3) ? 3'd3 : 3'd1;
          ent  <= ins[87:84];
          hb   <= ins[83:75];
          blk  <= 5'd0;
          x    <= 5'd0;
          xm   <= 5'd0;                                   // enroll / raw: in order
          b    <= 10'd0;
          rv   <= 3'd0;
          ones <= 3'd0;
          kc   <= 3'd0;
          K0   <= 192'd0;
          K1   <= 192'd0;
          st   <= (ins[91:88] == PF_ENROLL) ? U_KRD : (ins[91:88] == PF_RAW) ? U_REQ : U_BLK;
        end
        // ---- enroll: read the key shares (3 lanes) ----
        U_KRD: begin
          if (kc != 3'd0) begin                         // lanes 0, 1, 2 shift in: K = {l2, l1, l0}
            K0 <= {srd0, K0[191:64]};
            K1 <= {srd1, K1[191:64]};
          end
          if (kc == 3'd3) begin kc <= 3'd0; st <= U_REQ; end
          else kc <= kc + 3'd1;
        end
        // ---- reconstruct: start of a block ----
        U_BLK: st <= blk[0] ? U_MSK : U_HLD;
        U_HLD: begin hl <= brdata; st <= U_MSK; end
        U_MSK: begin
          R  <= rnd[5:0];
          xm <= rnd[10:6];
          wm <= (blk[0] ? hl[63:32] : hl[31:0]) ^ cwv(rnd[5:0]);
          x  <= 5'd0;
          st <= U_REQ;
        end
        U_REQ: st <= U_WAIT;
        U_WAIT: if (raw_done) begin
          case (mode)
            2'd0: begin                                   // enroll: 5 reads per bit
              if (rv != 3'd4) begin
                ones <= ones_n; rv <= rv + 3'd1; st <= U_REQ;
              end else begin
                ones <= 3'd0; rv <= 3'd0;
                hp   <= maj ^ cw(k0b, x);                 // r ^ C(k0)
                st   <= U_HB;
              end
            end
            2'd1: begin                                   // reconstruct: majority of nrd reads
              if ({1'b0, rv} != {1'b0, nrd} - 4'd1) begin
                ones <= ones_n; rv <= rv + 3'd1; st <= U_REQ;
              end else begin
                ones <= 3'd0; rv <= 3'd0;
                y[xr] <= rmaj ^ wm[xr];                   // bit xr of y = r' ^ w ^ C(R)
                x <= x + 5'd1;
                if (x == 5'd31) begin
                  u <= 5'd0; best <= 6'd63; st <= U_DEC;
                end else st <= U_REQ;
              end
            end
            default: begin                                // raw dump
              hl <= {raw_bit, hl[63:1]};
              b  <= b + 10'd1;
              st <= (b[5:0] == 6'd63) ? U_RWR : U_REQ;
            end
          endcase
        end
        // ---- decoder: one codeword pair per clock ----
        U_DEC: begin
          if (cand < best) begin
            best <= cand;
            bm   <= {u, use1};
          end
          u <= u + 5'd1;
          if (u == 5'd31) begin
            // decoded k^R (with this clock's candidate if it is the best) enters at the top
            K0 <= {((cand < best) ? {u, use1} : bm), K0[191:6]};
            K1 <= {R, K1[191:6]};
            if (blk == PUF_NB - 1) begin kc <= 3'd0; st <= U_KWR; end
            else begin blk <= blk + 5'd1; st <= U_BLK; end
          end
        end
        U_HB: begin                                       // + C(k1): the public helper bit
          hl <= {hp ^ cw(k1b, x), hl[63:1]};
          x  <= x + 5'd1;
          if (x == 5'd31) begin
            K0 <= {K0[5:0], K0[191:6]};                   // next block's bits to K[5:0]
            K1 <= {K1[5:0], K1[191:6]};
            if (blk[0]) st <= U_HWR;                      // two blocks = one helper lane
            else begin blk <= blk + 5'd1; st <= U_REQ; end
          end else st <= U_REQ;
        end
        U_HWR: begin
          // enrolled: write the key back in its canonical form (lanes 0..2, top 12
          // bits of lane 2 and lane 3 zero), so the microcode can hash its check value
          if (blk == PUF_NB - 1) begin kc <= 3'd0; st <= U_KWR; end
          else begin blk <= blk + 5'd1; st <= U_REQ; end
        end
        U_RWR: st <= (b == PUF_NR) ? U_IDLE : U_REQ;
        U_KWR: begin
          kc <= kc + 3'd1;
          if (kc == 3'd3) st <= U_IDLE;
        end
        default: st <= U_IDLE;
      endcase
    end
  end

`ifdef PQSE_TRACE
  always @(posedge clk) begin
    if (st == U_REQ && mode == 2'd0 && blk == 5'd0 && x == 5'd0 && rv == 3'd0)
      $display("[%0t] PUF enroll: key = %h (180 bits, simulation only)", $time,
               (K0[179:0] ^ K1[179:0]) );                 // canonical before the blocks
    if (st == U_KWR && kc == 3'd0)
      $display("[%0t] PUF %s (%0d read(s) per bit): key = %h (180 bits, simulation only)", $time,
               (mode == 2'd0) ? "enroll" : "reconstruct", (mode == 2'd0) ? 5 : nrd,
               (K0[191:12] ^ K1[191:12]));                // canonical after the 30 blocks
  end
`endif
endmodule
