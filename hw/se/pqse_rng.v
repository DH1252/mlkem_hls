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
//                share-1 halves. v5: the key and IV enter through the three
//                insertion points of the state (4 load clocks, the standard
//                Trivium initial state at the end) instead of a 288-bit
//                parallel load.
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
  input  wire         reseed,      // load K and IV (4 clocks + TRNG waits), then the 1152 initialization rounds
  output wire         seed_en,     // TRNG words wanted (loading)
  input  wire         seed_valid,  // a TRNG word is on seed
  input  wire [63:0]  seed,        // {32 K bits, 32 IV bits} per load clock 1..3 (MSB first)
  output wire         seed_take,   // that word is used this clock
  output wire         busy,
  input  wire         take,        // the bits on rnd are used this clock
  input  wire         take_hi,     // ... and only bits 63:32 (allowed one clock after a take)
  output wire [63:0]  rnd
);
  // v4 (area): 32 Trivium rounds per clock instead of 64. The 64-bit word W
  // gets 32 fresh bits at the top on every advance, so it is entirely fresh
  // two advances after a take; the generator keeps advancing until it is.
  // Rule (checked in simulation below): a take uses a fully fresh word, except
  // a take_hi one clock after a take (it uses only the top half, which is fresh).
  //
  // v5 (area): no parallel load. Trivium's state is three shift registers
  // A = s[92:0], B = s[176:93], C = s[287:177], each taking one new bit per
  // round at its bottom (t3 -> A, t1 -> B, t2 -> C). In the 4 load clocks
  // (128 rounds) those new bits are replaced by the initial state, oldest
  // position first: after round 127, A[j] / B[j] / C[j] is the bit inserted
  // in round 127 - j. So the inserted streams are, in round order,
  //   A: 48 zeros, then K[79] .. K[0]     (A = 13 zeros above K)
  //   B: 48 zeros, then IV[79] .. IV[0]   (B = 4 zeros above IV)
  //   C: 17 zeros, 1, 1, 1, then zeros    (C = 1, 1, 1 above 108 zeros)
  // K and IV are TRNG bits: load clocks 1, 2, 3 each take one 64-bit TRNG word
  // (waiting for it), K from seed[63:32], IV from seed[31:0], MSB first (in load
  // clock 1 rounds 32..47 insert zeros, so 16 bits of that word are unused).
  // Then 1152 rounds as usual.
  reg  [287:0] s;
  reg  [5:0]   icnt;
  reg          init;
  reg          ld;           // loading K / IV
  reg  [1:0]   lc;           // load clock 0..3
  reg  [63:0]  W;
  reg  [1:0]   fr;           // advances since the last take (2 = W fully fresh)
  reg  [287:0] ns;
  reg  [31:0]  z;
  reg          t1, t2, t3;
  integer i;

  // 32 Trivium rounds (the taps allow up to 64 in parallel: no chain); in a
  // load clock the three new bits come from the initial-state streams
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
      if (ld) begin
        // round 32 lc + i: A (t3) K, B (t1) IV from load clock 1 round 48 on;
        // C (t2) the three ones in rounds 17..19
        t3 = ((lc == 2'd0) || (lc == 2'd1 && i < 16)) ? 1'b0 : seed[63 - i];
        t1 = ((lc == 2'd0) || (lc == 2'd1 && i < 16)) ? 1'b0 : seed[31 - i];
        t2 = (lc == 2'd0) && (i >= 17) && (i <= 19);
      end
      ns = {ns[286:177], t2, ns[175:93], t1, ns[91:0], t3};
    end
  end

  assign busy       = init | ld | reseed | (masked_en && fr != 2'd2);
  assign seed_en    = ld;
  assign seed_take  = ld && (lc != 2'd0) && seed_valid;
  // W is cleared by a reseed and advances only with masking on and after the
  // initialization, so it is 0 whenever rnd must be 0
  assign rnd        = W;

  always @(posedge clk) begin
    if (rst) begin
      s    <= 288'd0;
      init <= 1'b0;
      ld   <= 1'b0;
      lc   <= 2'd0;
      icnt <= 6'd0;
      W    <= 64'd0;
      fr   <= 2'd0;
    end else if (reseed) begin
      ld   <= 1'b1;
      lc   <= 2'd0;
      init <= 1'b0;
      W    <= 64'd0;
      fr   <= 2'd0;
    end else if (ld) begin
      if (lc == 2'd0 || seed_valid) begin
        s  <= ns;
        lc <= lc + 2'd1;
        if (lc == 2'd3) begin
          ld   <= 1'b0;
          init <= 1'b1;
          icnt <= 6'd0;
        end
      end
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

`ifndef SYNTHESIS
  // a take of a word that is not fully fresh would reuse mask bits: stop the simulation
  always @(posedge clk) begin
    if (!rst && masked_en && !init && !ld && !reseed && take && fr != 2'd2 && !take_hi) begin
      $display("PRNG ERROR: random word taken %0d advance(s) after the previous take (t=%0t)", fr, $time);
      $finish;
    end
  end
`endif
endmodule
