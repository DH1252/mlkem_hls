// -----------------------------------------------------------------------------
// pqse_mem.v - memories of the PQSE secure element.
//
//   pqse_ram_1r1w   simple dual-port RAM: one write port, one read port with a
//                   registered output (read latency 1) and a read enable.
//                   Infers M10K/MLAB on Cyclone V, an SRAM macro or DFFRAM on
//                   an ASIC. RAMSTYLE: 0 = tool default, 1 = MLAB/LUTRAM
//                   (Gowin EDA: block RAM), 2 = block RAM (M10K / Gowin BSRAM;
//                   small RAMs the tools would otherwise put in LUTs).
//
// Instances (in pqse_core.v):
//   polynomial RAM   2 x (1024 x 25): RAM 0 holds the even slots (share 0 and
//                    public data), RAM 1 the odd slots (share 1); 16 slots x 128
//                    words, word w = {c[2w+1], c[2w]}, + an even-parity bit
//   I/O buffer       512 lanes x 4 16-bit words as two 1024 x 16 RAMs (even /
//                    odd words; the host writes 32-bit words)
//   seed registers   2 x (256 x 17): 16-bit words + parity, one RAM per Boolean
//                    share, so the two shares never share a RAM, a bit line or
//                    an output register
//
// Side-channel rules ("precharge"): the write-data buses of the polynomial RAMs
// are AND-gated with their write enables in pqse_core.v; the engines never
// write share 0 and share 1 of the same coefficient in consecutive clocks, and
// read them as share 0, a public word of RAM 0, (idle,) share 1; between
// instructions the sequencer reads RAM 1's zero slot and a public word of RAM 0.
// So neither the two output registers nor the read mux behind them ever hold,
// or switch between, the two shares of one coefficient.
// -----------------------------------------------------------------------------
module pqse_ram_1r1w #(
  parameter AW       = 11,
  parameter DW       = 24,
  parameter RAMSTYLE = 0
) (
  input  wire          clk,
  input  wire          we,
  input  wire [AW-1:0] waddr,
  input  wire [DW-1:0] wdata,
  input  wire          re,
  input  wire [AW-1:0] raddr,
  output reg  [DW-1:0] rdata
);
  generate
    if (RAMSTYLE == 1) begin : g_mlab
      // Quartus: MLAB. Yosys (gate counts, Gowin): its own attribute - it reads
      // "ramstyle" as a demand for a RAM type of that name and stops without one
`ifdef YOSYS
      (* no_rw_check *) reg [DW-1:0] mem [0:(1<<AW)-1];
`elsif PQSE_GOWIN_EDA
      // GowinSynthesis: block RAM, not shadow SRAM. The read is registered here
      // anyway, and the two seed RAMs as shadow SRAM cost ~800 logic units
      // (each RAM16 counts as 6) against one BSRAM each; one RAM per share
      // either way, so the shares still never share a RAM.
      reg [DW-1:0] mem [0:(1<<AW)-1] /* synthesis syn_ramstyle = "block_ram" */;
`else
      (* ramstyle = "MLAB, no_rw_check" *) reg [DW-1:0] mem [0:(1<<AW)-1];
`endif
`ifdef PQSE_SIM_INIT
      integer i;
      initial for (i = 0; i < (1<<AW); i = i + 1) mem[i] = {DW{1'b0}};
`endif
      always @(posedge clk) begin
        if (we) mem[waddr] <= wdata;
        if (re) rdata <= mem[raddr];
      end
    end else if (RAMSTYLE == 2) begin : g_blk
`ifdef YOSYS
      (* no_rw_check, ram_style = "block" *) reg [DW-1:0] mem [0:(1<<AW)-1];
`elsif PQSE_GOWIN_EDA
      reg [DW-1:0] mem [0:(1<<AW)-1] /* synthesis syn_ramstyle = "block_ram" */;
`else
      (* ramstyle = "M10K, no_rw_check" *) reg [DW-1:0] mem [0:(1<<AW)-1];
`endif
`ifdef PQSE_SIM_INIT
      integer i;
      initial for (i = 0; i < (1<<AW); i = i + 1) mem[i] = {DW{1'b0}};
`endif
      always @(posedge clk) begin
        if (we) mem[waddr] <= wdata;
        if (re) rdata <= mem[raddr];
      end
    end else begin : g_def
`ifdef YOSYS
      (* no_rw_check *) reg [DW-1:0] mem [0:(1<<AW)-1];
`elsif PQSE_GOWIN_EDA
      reg [DW-1:0] mem [0:(1<<AW)-1];     // GowinSynthesis: no bypass logic by default
`else
      (* ramstyle = "no_rw_check" *) reg [DW-1:0] mem [0:(1<<AW)-1];
`endif
`ifdef PQSE_SIM_INIT
      integer i;
      initial for (i = 0; i < (1<<AW); i = i + 1) mem[i] = {DW{1'b0}};
`endif
      always @(posedge clk) begin
        if (we) mem[waddr] <= wdata;
        if (re) rdata <= mem[raddr];
      end
    end
  endgenerate
endmodule
