// -----------------------------------------------------------------------------
// tb_pqse_gate.sv - pin-level testbench of the sky130 gate-level netlist of
// pqse_top, for switching activity (make se-power-vcd): a VCD of a window of
// one command, which OpenSTA turns into a power estimate (scripts/pqse_power.tcl).
//
// Only the chip's pins are used (the netlist is flat: no internal names):
// reset, wait until the power-on wipe is done, start a command over SPI, run
// +start=<clocks> into it, then dump +len=<clocks> and stop.
//   +cmd=<n>     command (default 1 KEYGEN: needs no input, TRNG seeds; the
//                synthesized pqse_top resets to lifecycle USER, where it is
//                allowed). 2 ENCAPS runs on the buffer as it is (all zero:
//                a valid ek of zeros)
//   +start=<n>   clocks after the command start before the dump (default 20000:
//                past the PRNG reseed, inside the first hashes)
//   +len=<n>     clocks dumped (default 2000; a flat netlist dump is large:
//                roughly 100-200 MB per 1000 clocks)
//   +vcd=<file>  output (default gate.vcd)
// The clock is 50 MHz (20 ns), the period scripts/pqse_power.tcl assumes.
// -----------------------------------------------------------------------------
`timescale 1ns / 1ps

module tb_pqse_gate;
  localparam int STATUS = 'h403, CTRL = 'h402, ID = 'h400;

  logic clk = 1'b0, rst_n = 1'b0;
  logic sck = 1'b0, cs_n = 1'b1, mosi = 1'b0, tamper = 1'b0;
  wire  miso, irq, trig;

  always #10 clk = ~clk;

  pqse_top dut (
    .clk(clk), .rst_n(rst_n), .spi_sck(sck), .spi_cs_n(cs_n), .spi_mosi(mosi),
    .spi_miso(miso), .irq(irq), .tamper(tamper), .trig(trig));

  // ---- SPI (mode 0, SCK = clk / 8), as in tb_pqse.sv ----
  task automatic spi_byte(input logic [7:0] o, output logic [7:0] i);
    for (int b = 7; b >= 0; b--) begin
      mosi = o[b];
      repeat (4) @(negedge clk);
      sck = 1'b1; i[b] = miso;
      repeat (4) @(negedge clk);
      sck = 1'b0;
    end
  endtask
  task automatic spi_rd(input int a, output logic [31:0] d);
    logic [7:0] x;
    cs_n = 1'b0; repeat (4) @(negedge clk);
    spi_byte(8'h03, x); spi_byte(8'(a >> 8), x); spi_byte(8'(a), x); spi_byte(8'h00, x);
    for (int k = 0; k < 4; k++) begin spi_byte(8'h00, x); d[8*k +: 8] = x; end
    repeat (4) @(negedge clk); cs_n = 1'b1; repeat (8) @(negedge clk);
  endtask
  task automatic spi_wr(input int a, input logic [31:0] d);
    logic [7:0] x;
    cs_n = 1'b0; repeat (4) @(negedge clk);
    spi_byte(8'h02, x); spi_byte(8'(a >> 8), x); spi_byte(8'(a), x);
    for (int k = 0; k < 4; k++) spi_byte(d[8*k +: 8], x);
    repeat (4) @(negedge clk); cs_n = 1'b1; repeat (8) @(negedge clk);
  endtask

  initial begin
    logic [31:0] st, id;
    int cmd, start, len, n;
    string vcd;
    if (!$value$plusargs("cmd=%d", cmd))     cmd   = 1;
    if (!$value$plusargs("start=%d", start)) start = 20000;
    if (!$value$plusargs("len=%d", len))     len   = 2000;
    if (!$value$plusargs("vcd=%s", vcd))     vcd   = "gate.vcd";

    repeat (8) @(negedge clk);
    rst_n = 1'b1;
    repeat (8) @(negedge clk);
    spi_rd(ID, id);
    $display("gate-level: ID = %08h (expected 50515345)", id);
    if (id != 32'h50515345) begin
      $display("ERROR: the netlist does not answer on SPI");
      $finish;
    end
    // power-on wipe (internal ZEROIZE): busy until done
    n = 0;
    do begin spi_rd(STATUS, st); n++; end while (st[0] && n < 2000);
    if (st[0]) begin
      $display("ERROR: still busy after the power-on wipe (STATUS %08h)", st);
      $finish;
    end
    $display("gate-level: idle, STATUS %08h; command %0d, dump from clock %0d for %0d clocks",
             st, cmd, start, len);
    spi_wr(CTRL, cmd);
    repeat (start) @(posedge clk);
    $dumpfile(vcd);
    $dumpvars(1, dut);            // the netlist's nets (not the cell models' internals)
    repeat (len) @(posedge clk);
    $display("gate-level: %0d clocks dumped to %s (Verilator VCD scope TOP/tb_pqse_gate/dut)", len, vcd);
    $finish;
  end
endmodule
