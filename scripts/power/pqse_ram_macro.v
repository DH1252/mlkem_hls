// -----------------------------------------------------------------------------
// pqse_ram_macro.v - the RAMs as SRAM macros for the sky130 power / timing
// estimate (make se-power RAM_MACRO=1): replaces hw/se/pqse_mem.v there.
//
// pqse_ram_1r1w (same parameters and ports) instantiates a black-box macro per
// shape, pqse_sram_a<AW>_d<DW>; scripts/power/pqse_sram_lib.py writes the matching
// Liberty stub (pins, a registered read: clock to rdata 2 ns, setup 0.5 ns, no
// power). The estimate then covers the logic only, as on a chip, where the RAMs
// would be SRAM macros with their own datasheet power: built from flip-flops
// they dominate it (every bit clocked every cycle) and their decode trees break
// the timing report. Shapes of v4 and v5; any other one stops synthesis.
// Not for simulation.
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
  output wire [DW-1:0] rdata
);
  generate
    if (AW == 10 && DW == 25) begin : g_a10_d25
      pqse_sram_a10_d25 u_m (.clk(clk), .we(we), .waddr(waddr), .wdata(wdata),
                               .re(re), .raddr(raddr), .rdata(rdata));
    end
    else if (AW == 10 && DW == 16) begin : g_a10_d16
      pqse_sram_a10_d16 u_m (.clk(clk), .we(we), .waddr(waddr), .wdata(wdata),
                               .re(re), .raddr(raddr), .rdata(rdata));
    end
    else if (AW == 8 && DW == 17) begin : g_a8_d17
      pqse_sram_a8_d17 u_m (.clk(clk), .we(we), .waddr(waddr), .wdata(wdata),
                               .re(re), .raddr(raddr), .rdata(rdata));
    end
    else if (AW == 8 && DW == 16) begin : g_a8_d16
      pqse_sram_a8_d16 u_m (.clk(clk), .we(we), .waddr(waddr), .wdata(wdata),
                               .re(re), .raddr(raddr), .rdata(rdata));
    end
    else if (AW == 7 && DW == 7) begin : g_a7_d7
      pqse_sram_a7_d7 u_m (.clk(clk), .we(we), .waddr(waddr), .wdata(wdata),
                               .re(re), .raddr(raddr), .rdata(rdata));
    end
    else if (AW == 9 && DW == 32) begin : g_a9_d32
      pqse_sram_a9_d32 u_m (.clk(clk), .we(we), .waddr(waddr), .wdata(wdata),
                               .re(re), .raddr(raddr), .rdata(rdata));
    end
    else if (AW == 6 && DW == 65) begin : g_a6_d65
      pqse_sram_a6_d65 u_m (.clk(clk), .we(we), .waddr(waddr), .wdata(wdata),
                               .re(re), .raddr(raddr), .rdata(rdata));
    end
    else if (AW == 6 && DW == 64) begin : g_a6_d64
      pqse_sram_a6_d64 u_m (.clk(clk), .we(we), .waddr(waddr), .wdata(wdata),
                               .re(re), .raddr(raddr), .rdata(rdata));
    end
    else begin : g_unsupported
      pqse_sram_shape_not_in_scripts_power_pqse_ram_macro_v u_m ();   // add the shape here and in pqse_sram_lib.py
    end
  endgenerate
endmodule

(* blackbox *)
module pqse_sram_a10_d25 (
  input  wire          clk,
  input  wire          we,
  input  wire [9:0]  waddr,
  input  wire [24:0] wdata,
  input  wire          re,
  input  wire [9:0]  raddr,
  output wire [24:0] rdata
);
endmodule

(* blackbox *)
module pqse_sram_a10_d16 (
  input  wire          clk,
  input  wire          we,
  input  wire [9:0]  waddr,
  input  wire [15:0] wdata,
  input  wire          re,
  input  wire [9:0]  raddr,
  output wire [15:0] rdata
);
endmodule

(* blackbox *)
module pqse_sram_a8_d17 (
  input  wire          clk,
  input  wire          we,
  input  wire [7:0]  waddr,
  input  wire [16:0] wdata,
  input  wire          re,
  input  wire [7:0]  raddr,
  output wire [16:0] rdata
);
endmodule

(* blackbox *)
module pqse_sram_a8_d16 (
  input  wire          clk,
  input  wire          we,
  input  wire [7:0]  waddr,
  input  wire [15:0] wdata,
  input  wire          re,
  input  wire [7:0]  raddr,
  output wire [15:0] rdata
);
endmodule

(* blackbox *)
module pqse_sram_a7_d7 (
  input  wire          clk,
  input  wire          we,
  input  wire [6:0]  waddr,
  input  wire [6:0] wdata,
  input  wire          re,
  input  wire [6:0]  raddr,
  output wire [6:0] rdata
);
endmodule

(* blackbox *)
module pqse_sram_a9_d32 (
  input  wire          clk,
  input  wire          we,
  input  wire [8:0]  waddr,
  input  wire [31:0] wdata,
  input  wire          re,
  input  wire [8:0]  raddr,
  output wire [31:0] rdata
);
endmodule

(* blackbox *)
module pqse_sram_a6_d65 (
  input  wire          clk,
  input  wire          we,
  input  wire [5:0]  waddr,
  input  wire [64:0] wdata,
  input  wire          re,
  input  wire [5:0]  raddr,
  output wire [64:0] rdata
);
endmodule

(* blackbox *)
module pqse_sram_a6_d64 (
  input  wire          clk,
  input  wire          we,
  input  wire [5:0]  waddr,
  input  wire [63:0] wdata,
  input  wire          re,
  input  wire [5:0]  raddr,
  output wire [63:0] rdata
);
endmodule
