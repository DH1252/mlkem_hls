// -----------------------------------------------------------------------------
// pqse_rng.v - random number generation of the PQSE secure element.
//
//   pqse_ro_src  entropy source: NRO free-running ring oscillators, XORed and
//                sampled by the system clock (2-flop synchronizer). Powered only
//                while enabled.
//                  PQSE_FPGA        ring oscillators from LUT inverters (Quartus keeps
//                                   the combinational loops; constrain them with
//                                   LogicLock for stable placement)
//                  PQSE_ASIC_SKY130 sky130_fd_sc_hd inverter / nand cells
//                  (default)        simulation model: xorshift32 (deterministic)
//   pqse_trng    oversampling (XOR of OSR samples per bit), SP 800-90B health
//                tests (repetition count, adaptive proportion), 64-bit words.
//                The words are conditioned by SHA3-256 in the Keccak engine
//                (HASH source TRNG) before they become seeds d, z, m, nonces.
//   pqse_prng    Trivium (eSTREAM) keystream generator, 32 bits per clock into
//                a 64-bit word (fully fresh two clocks after a take; only
//                takers of the top half may take in consecutive clocks - checked
//                in simulation), reseeded from the TRNG at the start of every
//                command; supplies the masks and the shuffling/dummy-cycle
//                randomness. Outputs 0 when masking is disabled, so the masked
//                datapaths then compute the plain values and stop toggling their
//                share-1 halves.
//
// UNTESTED FIRST VERSION - see hw/se/README.md.
// -----------------------------------------------------------------------------
module pqse_ro_src #(
  parameter NRO = 8
) (
  input  wire clk,
  input  wire rst,
  input  wire en,
  output reg  raw
);
  reg s1;
`ifdef PQSE_FPGA
  // NRO oscillators of different odd lengths (5, 7, 9, ...) to avoid locking
  wire [NRO-1:0] ro_out;
  genvar g, k;
  generate
    for (g = 0; g < NRO; g = g + 1) begin : g_ro
      localparam L = 5 + 2*g;
      (* keep = 1 *) wire [L-1:0] n;
      assign n[0] = ~(n[L-1] & en);
      for (k = 1; k < L; k = k + 1) begin : g_inv
        assign n[k] = ~n[k-1];
      end
      assign ro_out[g] = n[L-1];
    end
  endgenerate
  wire mix = ^ro_out;
`elsif PQSE_ASIC_SKY130
  wire [NRO-1:0] ro_out;
  genvar g, k;
  generate
    for (g = 0; g < NRO; g = g + 1) begin : g_ro
      localparam L = 5 + 2*g;
      wire [L-1:0] n;
      sky130_fd_sc_hd__nand2_1 u_en (.A(n[L-1]), .B(en), .Y(n[0]));
      for (k = 1; k < L; k = k + 1) begin : g_inv
        sky130_fd_sc_hd__inv_1 u_inv (.A(n[k-1]), .Y(n[k]));
      end
      assign ro_out[g] = n[L-1];
    end
  endgenerate
  wire mix = ^ro_out;
`else
  // simulation model
  function [31:0] xs_next(input [31:0] v);
    reg [31:0] t;
    begin
      t = v ^ (v << 13);
      t = t ^ (t >> 17);
      xs_next = t ^ (t << 5);
    end
  endfunction
  reg [31:0] xs;
  always @(posedge clk) begin
    if (rst) xs <= 32'h2545F491;
    else if (en) xs <= xs_next(xs);
  end
  wire mix = xs[31] ^ xs[7];
`endif
  always @(posedge clk) begin
    s1  <= mix;      // first synchronizer stage (may go metastable: that is the point)
    raw <= s1;
  end
endmodule


module pqse_trng #(
  parameter OSR     = 4,     // raw samples XORed into one bit
  parameter RCT_CUT = 41,    // repetition count cutoff, H = 0.5 bit/sample, alpha = 2^-20
  parameter APT_W   = 1024,  // adaptive proportion window
  parameter APT_CUT = 800    // adaptive proportion cutoff for H = 0.5, alpha ~ 2^-20
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        en,      // collect (the oscillators run only while en = 1)
  input  wire        take,    // consume the current word
  output reg  [63:0] word,
  output wire        valid,   // 64 fresh bits in word, and the source is healthy
  output reg         fail,    // sticky health-test failure (cleared by reset only)
  output reg         ok       // startup test passed (one full APT window)
);
  wire raw;
  pqse_ro_src u_src (.clk(clk), .rst(rst), .en(en), .raw(raw));

  reg  [2:0]  osc;            // oversampling counter
  reg         fold;
  reg  [6:0]  nb;             // bits in word
  reg  [5:0]  rct;            // repetition count
  reg         last;
  reg  [10:0] apos;           // position in the APT window
  reg  [10:0] acnt;           // occurrences of the window's first bit
  reg         aref;
  reg         en_d;

  wire bit_rdy = en_d && (osc == OSR - 1);
  wire nbit    = fold ^ raw;

  assign valid = (nb == 7'd64) && ok && !fail;

  always @(posedge clk) begin
    if (rst) begin
      osc  <= 3'd0;
      fold <= 1'b0;
      nb   <= 7'd0;
      rct  <= 6'd0;
      apos <= 11'd0;
      acnt <= 11'd0;
      fail <= 1'b0;
      ok   <= 1'b0;
      en_d <= 1'b0;
      last <= 1'b0;
      aref <= 1'b0;
      word <= 64'd0;
    end else begin
      en_d <= en;            // skip the first clock after enabling (synchronizer)
      if (take) nb <= 7'd0;
      if (bit_rdy) begin
        osc  <= 3'd0;
        fold <= 1'b0;
        // --- repetition count test ---
        if (nbit == last) begin
          if (rct == RCT_CUT - 1) fail <= 1'b1;
          else rct <= rct + 6'd1;
        end else begin
          rct <= 6'd1;
        end
        last <= nbit;
        // --- adaptive proportion test ---
        if (apos == 11'd0) begin
          aref <= nbit;
          acnt <= 11'd1;
          apos <= 11'd1;
        end else begin
          if (nbit == aref) begin
            if (acnt == APT_CUT - 1) fail <= 1'b1;
            acnt <= acnt + 11'd1;
          end
          if (apos == APT_W - 1) begin
            apos <= 11'd0;
            ok   <= 1'b1;          // a full window passed
          end else begin
            apos <= apos + 11'd1;
          end
        end
        // --- output word ---
        if (!take && nb != 7'd64) begin
          word <= {word[62:0], nbit};
          nb   <= nb + 7'd1;
        end
      end else if (en_d) begin
        osc  <= osc + 3'd1;
        fold <= nbit;
      end
    end
  end
endmodule


module pqse_prng (
  input  wire         clk,
  input  wire         rst,
  input  wire         masked_en,   // 0: rnd is always 0 (masking off)
  input  wire         reseed,      // load seed and run the 1152 initialization rounds
  input  wire [159:0] seed,        // {IV[79:0], K[79:0]}
  output wire         busy,
  input  wire         take,        // the bits on rnd are used this clock
  input  wire         take_hi,     // ... and only bits 63:32 (allowed one clock after a take)
  output wire [63:0]  rnd,
  output reg          ferr         // a take of a stale word (masks reused): a fault
);
  // v4 (area): 32 Trivium rounds per clock instead of 64. The 64-bit word W
  // gets 32 fresh bits at the top on every advance, so it is entirely fresh
  // two advances after a take; the generator keeps advancing until it is.
  // Rule (checked in hardware below): a take uses a fully fresh word, except
  // a take_hi one clock after a take (it uses only the top half, which is fresh).
  // The microcode and the engines never break it; a fault can (a flipped fr,
  // a skipped wait, a take forced early), and the reused mask bits would unmask
  // a share: ferr is set (until the engine reset) and the core aborts with FAULT.
  reg  [287:0] s;
  reg  [5:0]   icnt;
  reg          init;
  reg  [63:0]  W;
  reg  [1:0]   fr;           // advances since the last take (2 = W fully fresh)
  reg  [287:0] ns;
  reg  [31:0]  z;
  reg          t1, t2, t3;
  integer i;

  // 32 Trivium rounds (the taps allow up to 64 in parallel: no chain)
  always @* begin
    ns = s;
    for (i = 0; i < 32; i = i + 1) begin
      t1 = ns[65]  ^ ns[92];
      t2 = ns[161] ^ ns[176];
      t3 = ns[242] ^ ns[287];
      z[i] = t1 ^ t2 ^ t3;
      t1 = t1 ^ (ns[90]  & ns[91])  ^ ns[170];
      t2 = t2 ^ (ns[174] & ns[175]) ^ ns[263];
      t3 = t3 ^ (ns[285] & ns[286]) ^ ns[68];
      ns = {ns[286:177], t2, ns[175:93], t1, ns[91:0], t3};
    end
  end

  assign busy = init | reseed | (masked_en && fr != 2'd2);
  assign rnd  = (masked_en && !init) ? W : 64'd0;

  wire stale = masked_en && !init && !reseed && take && fr != 2'd2 && !take_hi;

  always @(posedge clk) begin
    if (rst) ferr <= 1'b0;
    else     ferr <= ferr | stale;
  end

  always @(posedge clk) begin
    if (rst) begin
      s    <= 288'd0;
      init <= 1'b0;
      icnt <= 6'd0;
      W    <= 64'd0;
      fr   <= 2'd0;
    end else if (reseed) begin
      // A: K (80) then 13 zeros; B: IV (80) then 4 zeros; C: 108 zeros then 1,1,1
      s    <= {3'b111, 108'd0, 4'd0, seed[159:80], 13'd0, seed[79:0]};
      init <= 1'b1;
      icnt <= 6'd0;
      fr   <= 2'd0;
    end else if (init) begin
      s <= ns;
      if (icnt == 6'd35) init <= 1'b0;     // 36 x 32 = 1152 rounds
      icnt <= icnt + 6'd1;
    end else if (masked_en && (take || fr != 2'd2)) begin
      s  <= ns;
      W  <= {z, W[63:32]};
      fr <= take ? 2'd1 : fr + 2'd1;
    end
  end

`ifdef PQSE_FAULT_CAMPAIGN
  // fault campaign (tb_pqse_fault.sv): records that a reuse happened (the core
  // then aborts with FAULT through ferr); cleared by the testbench only
  reg reuse = 1'b0;
  always @(posedge clk)
    if (!rst && stale) reuse <= 1'b1;
`elsif SYNTHESIS
`else
  always @(posedge clk)
    if (!rst && stale)
      $display("PRNG: random word taken %0d advance(s) after the previous take (t=%0t): fault",
               fr, $time);
`endif
endmodule
