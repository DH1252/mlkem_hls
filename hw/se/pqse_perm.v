// -----------------------------------------------------------------------------
// pqse_perm.v - random permutations for the PQSE shuffling (hiding).
//
// A 128 x 7 table T holds uniformly random permutations drawn with the
// "inside-out" Fisher-Yates shuffle:
//
//   for i = 0 .. n-1:  j := uniform in 0..i;  T[i] := T[j];  T[j] := i
//
// v5 (area): T is block RAM with registered reads (two copies written
// together: one read port for the generator, one for the lookups), instead of
// two LUT-RAM copies with asynchronous reads. Three clocks per element: read
// T[j], write T[i] := T[j], write T[j] := i; j = floor(r * (i+1) / 2^24) from
// 24 fresh PRNG bits (bias below 128 / 2^24 = 8e-6). Entries are only read
// after they were written, so the table needs no initialization.
//
// Lookup: the consumer puts on idx the index it needs in the NEXT clock (the
// read is registered); val is T[that index] in that clock, held while idx
// stays the same.
//
//   n64 = 0  (PWM, ADD, MSPLIT, masked Compress / mu / CBD): one permutation of
//            0..127, drawn before the instruction starts (start, busy).
//   n64 = 1  (NTT, INTT): two halves of 64 entries. The first layer's
//            permutation is drawn before the instruction (start, busy); while
//            a layer runs on one half, the next layer's permutation is drawn
//            into the other half (192 clocks; the layer takes 137, so the poly
//            unit waits for "ready" at the end of the layer); the poly unit
//            flips halves with "next" at the end of a layer. Every NTT layer
//            thus runs in its own independent, uniformly random order.
// The lookup port (idx -> val) and the generator's read use different RAM
// copies, so drawing in the background never disturbs the running layer.
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
  input  wire [6:0]  idx,       // lookup: the index needed next clock
  output wire [6:0]  val
);
  reg        m64;      // NTT mode
  reg        cur;      // NTT mode: the half the lookups use
  reg        gact;     // drawing
  reg        gfg;      // ... the instruction's first permutation (the sequencer waits)
  reg  [1:0] gph;      // 0: read T[j], 1: T[i] := T[j], 2: T[j] := i
  reg        ghalf;    // NTT mode: the half being drawn
  reg  [2:0] lay;      // NTT mode: the layer now running (0..6)
  reg  [6:0] gi, gj, glast;

  // j = floor(r * (i + 1) / 2^24), 0 .. i
  wire [7:0]  ip1  = {1'b0, gi} + 8'd1;
  wire [31:0] prod = {8'd0, rnd[23:0]} * {24'd0, ip1};
  wire [6:0]  jn   = prod[30:24];

  wire [6:0]  gbase = m64 ? {ghalf, 6'd0} : 7'd0;

  // the single write port, into both copies
  wire        t_we = gact && (gph != 2'd0);
  wire [6:0]  t_wa = gbase | ((gph == 2'd1) ? gi : gj);
  wire [6:0]  rb;                                        // generator copy: T[j] (read in gph 0)
  wire [6:0]  t_wd = (gph == 2'd1) ? rb : gi;
  pqse_ram_1r1w #(.AW(7), .DW(7), .RAMSTYLE(2)) u_tb (
    .clk(clk), .we(t_we), .waddr(t_wa), .wdata(t_wd),
    .re(gact && (gph == 2'd0)), .raddr(gbase | jn), .rdata(rb));
  // lookup copy: read every clock; the half flips with "next" in the same clock
  wire        cur_n = (m64 && next) ? ~cur : cur;
  wire [6:0]  ra;
  pqse_ram_1r1w #(.AW(7), .DW(7), .RAMSTYLE(2)) u_ta (
    .clk(clk), .we(t_we), .waddr(t_wa), .wdata(t_wd),
    .re(1'b1), .raddr(m64 ? {cur_n, idx[5:0]} : idx), .rdata(ra));

  assign val      = m64 ? {1'b0, ra[5:0]} : ra;
  assign busy     = start | (gact && gfg);
  assign ready    = !gact;
  // (every PRNG word goes to one user only: the background draw runs only while
  //  an NTT layer runs, and the poly unit takes no randomness during an NTT)
  assign rnd_take = gact && (gph == 2'd0);

  always @(posedge clk) begin
    if (rst) begin
      gact <= 1'b0;
      gph  <= 2'd0;
      cur  <= 1'b0;
      m64  <= 1'b0;
    end else if (start) begin                            // aborts a background draw
      m64   <= n64;
      cur   <= 1'b0;
      lay   <= 3'd0;
      ghalf <= 1'b0;
      gi    <= 7'd0;
      gph   <= 2'd0;
      glast <= n64 ? 7'd63 : 7'd127;
      gact  <= 1'b1;
      gfg   <= 1'b1;
    end else begin
      if (gact) begin
        case (gph)
          2'd0: begin gj <= jn; gph <= 2'd1; end         // T[j] read issued
          2'd1: gph <= 2'd2;                             // T[i] := T[j]
          default: begin                                 // T[j] := i
            gph <= 2'd0;
            gi  <= gi + 7'd1;
            if (gi == glast) begin
              gact <= 1'b0;
              gfg  <= 1'b0;
            end
          end
        endcase
      end
      // NTT mode: after the first draw, draw layer 1's order into the other half
      if (m64 && gact && gfg && gph == 2'd2 && gi == glast) begin
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
        gph   <= 2'd0;
        gact  <= (lay != 3'd5);
        gfg   <= 1'b0;
      end
    end
  end
endmodule
