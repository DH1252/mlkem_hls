// -----------------------------------------------------------------------------
// pqse_perm.v - random permutations for the PQSE shuffling (hiding).
//
// A 128 x 7 register file T (one write port, two asynchronous read ports;
// LUT RAM / MLAB on an FPGA, a 2R1W register file or latch array on a chip -
// no flip-flop array, no big multiplexers) holds uniformly random
// permutations drawn with the "inside-out" Fisher-Yates shuffle:
//
//   for i = 0 .. n-1:  j := uniform in 0..i;  T[i] := T[j];  T[j] := i
//
// two clocks per element (one write each), j = floor(r * (i+1) / 2^24) from 24
// fresh PRNG bits (bias below 128 / 2^24 = 8e-6). Entries are only read after
// they were written, so the file needs no initialization.
//
//   n64 = 0  (PWM, ADD, MSPLIT, masked Compress / mu / CBD): one permutation of
//            0..127, drawn before the instruction starts (start, busy).
//   n64 = 1  (NTT, INTT): two halves of 64 entries. The first layer's
//            permutation is drawn before the instruction (start, busy); while
//            a layer runs on one half, the next layer's permutation is drawn
//            into the other half (128 clocks, the layer takes 137); the poly
//            unit flips halves with "next" at the end of a layer and waits
//            for "ready" if the draw were ever late. Every NTT layer thus runs
//            in its own independent, uniformly random order.
// The lookup port (idx -> val) and the generator's read use different read
// ports, so drawing in the background never disturbs the running layer.
// -----------------------------------------------------------------------------
module pqse_perm (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,     // draw the permutation for the next instruction
  input  wire        n64,       // 1: NTT mode (64-entry halves), 0: one permutation of 0..127
  input  wire        next,      // NTT layer finished: switch to the other half
  output wire        busy,      // the instruction's first permutation is being drawn
  output wire        ready,     // the next layer's permutation is complete
  input  wire [63:0] rnd,
  output wire        rnd_take,
  input  wire [6:0]  idx,       // lookup
  output wire [6:0]  val
);
`ifdef PQSE_LUTRAM_1R
  // LUT RAM with one read port (Gowin shadow SRAM): two copies written together,
  // Ta for the lookup port, Tb for the generator
  reg [6:0] Ta [0:127];
  reg [6:0] Tb [0:127];
`elsif YOSYS
  (* no_rw_check *) reg [6:0] T [0:127];
`else
  (* ramstyle = "MLAB, no_rw_check" *) reg [6:0] T [0:127];
`endif

  reg        m64;      // NTT mode
  reg        cur;      // NTT mode: the half the lookups use
  reg        gact;     // drawing
  reg        gfg;      // ... the instruction's first permutation (the sequencer waits)
  reg        gph;      // 0: T[i] := T[j], 1: T[j] := i
  reg        ghalf;    // NTT mode: the half being drawn
  reg  [2:0] lay;      // NTT mode: the layer now running (0..6)
  reg  [6:0] gi, gj, glast;

  // j = floor(r * (i + 1) / 2^24), 0 .. i
  wire [7:0]  ip1  = {1'b0, gi} + 8'd1;
  wire [31:0] prod = {8'd0, rnd[23:0]} * {24'd0, ip1};
  wire [6:0]  jn   = prod[30:24];

  wire [6:0]  gbase = m64 ? {ghalf, 6'd0} : 7'd0;
`ifdef PQSE_LUTRAM_1R
  wire [6:0]  rb    = Tb[gbase | jn];                    // read port B: generator
  wire [6:0]  ra    = Ta[m64 ? {cur, idx[5:0]} : idx];   // read port A: lookup
`else
  wire [6:0]  rb    = T[gbase | jn];                     // read port B: generator
  wire [6:0]  ra    = T[m64 ? {cur, idx[5:0]} : idx];    // read port A: lookup
`endif

  assign val      = m64 ? {1'b0, ra[5:0]} : ra;
  assign busy     = start | (gact && gfg);
  assign ready    = !gact;
  // (every PRNG word goes to one user only: the background draw runs only while
  //  an NTT layer runs, and the poly unit takes no randomness during an NTT)
  assign rnd_take = gact && !gph;

  // the single write port
  always @(posedge clk) begin
    if (gact) begin
`ifdef PQSE_LUTRAM_1R
      if (!gph) begin Ta[gbase | gi] <= rb; Tb[gbase | gi] <= rb; end   // T[i] := T[j]
      else      begin Ta[gbase | gj] <= gi; Tb[gbase | gj] <= gi; end   // T[j] := i
`else
      if (!gph) T[gbase | gi] <= rb;                     // T[i] := T[j]
      else      T[gbase | gj] <= gi;                     // T[j] := i
`endif
    end
  end

  always @(posedge clk) begin
    if (rst) begin
      gact <= 1'b0;
      gph  <= 1'b0;
      cur  <= 1'b0;
      m64  <= 1'b0;
    end else if (start) begin                            // aborts a background draw
      m64   <= n64;
      cur   <= 1'b0;
      lay   <= 3'd0;
      ghalf <= 1'b0;
      gi    <= 7'd0;
      gph   <= 1'b0;
      glast <= n64 ? 7'd63 : 7'd127;
      gact  <= 1'b1;
      gfg   <= 1'b1;
    end else begin
      if (gact) begin
        if (!gph) begin
          gj  <= jn;
          gph <= 1'b1;
        end else begin
          gph <= 1'b0;
          gi  <= gi + 7'd1;
          if (gi == glast) begin
            gact <= 1'b0;
            gfg  <= 1'b0;
          end
        end
      end
      // NTT mode: after the first draw, draw layer 1's order into the other half
      if (m64 && gact && gfg && gph && gi == glast) begin
        gact  <= 1'b1;
        gfg   <= 1'b0;
        ghalf <= 1'b1;
        gi    <= 7'd0;
      end
      // a layer ended: the drawn half becomes current, the old one is redrawn for
      // the layer after - unless the layer now starting is the last (6): no draw
      // then, so the PRNG is never shared with the instruction that follows
      if (m64 && next) begin
        cur   <= ~cur;
        lay   <= lay + 3'd1;
        ghalf <= cur;
        gi    <= 7'd0;
        gph   <= 1'b0;
        gact  <= (lay != 3'd5);
        gfg   <= 1'b0;
      end
    end
  end
endmodule
