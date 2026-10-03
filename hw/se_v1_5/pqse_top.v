// -----------------------------------------------------------------------------
// pqse_top.v - top levels of the PQSE secure element.
//
//   pqse_top      the chip: SPI slave (4 pins), IRQ, tamper input, trigger
//   pqse_avalon   the FPGA demo: the same register map as an Avalon-MM slave
//                 (word addresses, read latency 1) for Platform Designer, so the
//                 board can be driven over JTAG (System Console) or by the ARM
//
// Parameters
//   MASKED   1: first-order masking of every secret (default). 0: unprotected
//            reference build (no share-1 seed storage, masked Keccak off, all
//            masks zero) for area/power comparison and as the TVLA positive
//            control; the same microcode runs, share 1 is then always zero.
//   RAMSTYLE 1: polynomial RAM in MLABs (Cyclone V), 0: tool default
//   PUF_WIN  ring-oscillator counting window in clocks
//   LC_RESET lifecycle after reset (0 TEST for development, 2 USER for a demo)
//
// trig: measurement trigger for side-channel evaluation on silicon / the
// board (scripts/pqse_tvla.py board): high from the start of the masked
// comparison window (M_OKINI) to its end (M_OKCHK), in lifecycle TEST only;
// 0 in every other lifecycle state, so a deployed device gives an attacker no
// timing reference.
//
// UNTESTED FIRST VERSION - see hw/se/README.md.
// -----------------------------------------------------------------------------
module pqse_sys #(
  parameter       MASKED   = 1,
  parameter       RAMSTYLE = 0,
  parameter       PUF_WIN  = 2048,
  parameter [1:0] LC_RESET = 2'd0
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        bus_we,
  input  wire        bus_re,
  input  wire [11:0] bus_addr,
  input  wire [31:0] bus_wdata,
  output wire [31:0] bus_rdata,
  output wire        irq,
  input  wire        tamper,
  output wire        trig
);
  wire        core_rst, cmd_start, cmd_inj, kexp, hide_en, core_busy, core_done;
  wire        key_valid, sk_valid, trng_ok, trng_fail, lc_is_test, core_trig;
  wire [7:0]  cmd, core_result;
  wire [2:0]  cmd_k, key_k;
  wire [31:0] cycles, h_wdata, h_rdata;
  wire        h_we, h_re;
  wire [9:0]  h_addr;

  pqse_host #(.LC_RESET(LC_RESET)) u_host (
    .clk(clk), .rst(rst),
    .bus_we(bus_we), .bus_re(bus_re), .bus_addr(bus_addr), .bus_wdata(bus_wdata),
    .bus_rdata(bus_rdata), .irq(irq), .tamper(tamper),
    .core_rst(core_rst), .cmd_start(cmd_start), .cmd(cmd), .cmd_k(cmd_k), .key_k(key_k),
    .cmd_inj(cmd_inj), .kexp(kexp),
    .hide_en(hide_en), .lc_is_test(lc_is_test),
    .core_busy(core_busy), .core_done(core_done), .core_result(core_result),
    .key_valid(key_valid), .sk_valid(sk_valid), .trng_ok(trng_ok), .trng_fail(trng_fail),
    .cycles(cycles),
    .h_we(h_we), .h_re(h_re), .h_addr(h_addr), .h_wdata(h_wdata), .h_rdata(h_rdata));

  pqse_core #(.MASKED(MASKED), .RAMSTYLE(RAMSTYLE), .PUF_WIN(PUF_WIN)) u_core (
    .clk(clk), .rst(rst | core_rst),
    .cmd_start(cmd_start), .cmd(cmd), .cmd_k(cmd_k), .key_k(key_k),
    .cmd_inj(cmd_inj), .kexp(kexp), .hide_en(hide_en),
    .trig(core_trig),
    .busy(core_busy), .done(core_done), .result(core_result), .key_valid(key_valid),
    .sk_valid(sk_valid), .trng_fail(trng_fail), .trng_ok(trng_ok), .cycles(cycles),
    .h_we(h_we), .h_re(h_re), .h_addr(h_addr), .h_wdata(h_wdata), .h_rdata(h_rdata));

  // registered, so the pin does not carry a combinational path from the core
  reg trig_q;
  always @(posedge clk) trig_q <= core_trig & lc_is_test;
  assign trig = trig_q;
endmodule


module pqse_top #(
  parameter       MASKED   = 1,
  parameter       RAMSTYLE = 0,
  parameter       PUF_WIN  = 2048,
  parameter [1:0] LC_RESET = 2'd2
) (
  input  wire clk,
  input  wire rst_n,
  input  wire spi_sck,
  input  wire spi_cs_n,
  input  wire spi_mosi,
  output wire spi_miso,
  output wire irq,
  input  wire tamper,
  output wire trig
);
  // reset from the pin: asserted asynchronously (from the first instant rst_n is
  // low, whatever the flip-flops powered up with), released synchronously. A
  // purely synchronous reset left the logic running unreset for two clocks at
  // power-up: with random (in simulation all-zero) registers the security-state
  // shadows disagreed, the host saw tampering and the persistent store burned
  // KILLED before the reset took hold.
  reg [1:0] rs;
  always @(posedge clk or negedge rst_n)
    if (!rst_n) rs <= 2'b11;
    else        rs <= {rs[0], 1'b0};
  wire rst = rs[1];

  wire        bus_we, bus_re;
  wire [11:0] bus_addr;
  wire [31:0] bus_wdata, bus_rdata;

  pqse_spi u_spi (
    .clk(clk), .rst(rst), .sck(spi_sck), .cs_n(spi_cs_n), .mosi(spi_mosi), .miso(spi_miso),
    .bus_we(bus_we), .bus_re(bus_re), .bus_addr(bus_addr), .bus_wdata(bus_wdata),
    .bus_rdata(bus_rdata));

  pqse_sys #(.MASKED(MASKED), .RAMSTYLE(RAMSTYLE), .PUF_WIN(PUF_WIN), .LC_RESET(LC_RESET)) u_sys (
    .clk(clk), .rst(rst), .bus_we(bus_we), .bus_re(bus_re), .bus_addr(bus_addr),
    .bus_wdata(bus_wdata), .bus_rdata(bus_rdata), .irq(irq), .tamper(tamper), .trig(trig));
endmodule


module pqse_avalon #(
  parameter       MASKED   = 1,
  parameter       RAMSTYLE = 0,
  parameter       PUF_WIN  = 2048,
  parameter [1:0] LC_RESET = 2'd0
) (
  input  wire        clk,
  input  wire        reset,
  input  wire [11:0] avs_address,
  input  wire        avs_read,
  input  wire        avs_write,
  input  wire [31:0] avs_writedata,
  output wire [31:0] avs_readdata,
  output wire        irq,
  input  wire        tamper,
  output wire        trig
);
  pqse_sys #(.MASKED(MASKED), .RAMSTYLE(RAMSTYLE), .PUF_WIN(PUF_WIN), .LC_RESET(LC_RESET)) u_sys (
    .clk(clk), .rst(reset), .bus_we(avs_write), .bus_re(avs_read), .bus_addr(avs_address),
    .bus_wdata(avs_writedata), .bus_rdata(avs_readdata), .irq(irq), .tamper(tamper), .trig(trig));
endmodule
