// -----------------------------------------------------------------------------
// tb_pqse_gate.sv - pin-level testbench of the sky130 gate-level netlist of
// pqse_top, for switching activity (make se-power-vcd): a SAIF (or VCD) of one
// command or a window of it, which OpenSTA turns into power
// (scripts/pqse_power.tcl), and scripts/power/pqse_energy.py into energy.
//
// Only the chip's pins are driven (the netlist is flat): reset, wait until the
// power-on wipe is done, clear the done flag, start a command over SPI, then
// measure:
//   +len=0       (default) the whole command: from its start until the chip
//                raises irq (done) - no SPI traffic inside the window
//   +len=<n>     n clocks, from +start=<n> clocks after the command start
//   +cmd=<n>     command (default 1 KEYGEN: needs no input, TRNG seeds; the
//                synthesized pqse_top resets to lifecycle USER, where it is
//                allowed). 2 ENCAPS runs on the buffer as it is (all zero:
//                a valid ek of zeros)
//   +vcd=<file>  output (default gate.vcd); a build with --trace-saif writes
//                SAIF (toggle counts per net: megabytes for a whole command,
//                where a VCD would be tens of GB)
//   +max=<n>     give up after n clocks in the window (default 20000000)
// The dump holds every cell instance's pins ($dumpvars(0, dut)): OpenSTA
// annotates activity on pins, <instance>/<pin> below the scope. It opens at the
// window start and the simulation ends at the window end, so the dump's time
// span is the window (OpenSTA divides the toggle counts by it).
// win is 1 inside the window (the SRAM macro models count accesses only then).
// gl_run.txt gets window_clocks <n> / command_clocks <n> (0 for a window: the
// command did not finish) / period_ns 20 / cmd <n> / full <0|1>.
// The clock is 50 MHz (20 ns), the period scripts/pqse_power.tcl assumes.
// -----------------------------------------------------------------------------
`timescale 1ns / 1ps

module tb_pqse_gate;
  localparam int STATUS = 'h403, CTRL = 'h402, ID = 'h400;

  logic clk = 1'b0, rst_n = 1'b0;
  logic sck = 1'b0, cs_n = 1'b1, mosi = 1'b0, tamper = 1'b0;
  logic win = 1'b0;                 // measurement window (SRAM models count in it)
  longint nwin = 0;                 // clocks in the window
  longint maxc = 20000000;
  wire  miso, irq, trig;

  always #10 clk = ~clk;
  always @(posedge clk) if (win) begin
    nwin <= nwin + 1;
    if (nwin > 0 && nwin % 100000 == 0) $display("gate-level: %0d clocks", nwin);
    if (nwin >= maxc) begin
      $display("ERROR: no irq after %0d clocks (+max)", nwin);
      $finish;
    end
  end

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
    int cmd, start, len, n, fd;
    longint mx;
    string vcd;
    if (!$value$plusargs("cmd=%d", cmd))     cmd   = 1;
    if (!$value$plusargs("start=%d", start)) start = 0;
    if (!$value$plusargs("len=%d", len))     len   = 0;
    if (!$value$plusargs("vcd=%s", vcd))     vcd   = "gate.vcd";
    if ($value$plusargs("max=%d", mx))       maxc  = mx;
    fd = $fopen("sram_access.txt", "w");     // the SRAM models append at the end
    $fclose(fd);

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
    spi_wr(STATUS, 32'h2);                   // clear done (irq) before the command
    repeat (4) @(negedge clk);
    if (irq) begin
      $display("ERROR: irq still high after clearing done");
      $finish;
    end
    $display("gate-level: idle; command %0d, %s", cmd,
             (len == 0) ? "whole command" : $sformatf("window from clock %0d, %0d clocks", start, len));
    spi_wr(CTRL, cmd);                       // the command starts at the end of this write
    if (len != 0) repeat (start) @(posedge clk);
    $dumpfile(vcd);
    $dumpvars(0, dut);                       // nets and every cell instance's pins
    win = 1'b1;
    if (len == 0) wait (irq === 1'b1);       // done
    else          repeat (len) @(posedge clk);
    @(posedge clk);
    win = 1'b0;
    // no more activity: the dump ends here (the simulation stops), so its time
    // span is the window
    $display("gate-level: %0d clocks measured%s", nwin,
             (len == 0) ? " (the whole command)" : "");
    fd = $fopen("gl_run.txt", "w");
    $fdisplay(fd, "window_clocks %0d", nwin);
    $fdisplay(fd, "command_clocks %0d", (len == 0) ? nwin : 0);
    $fdisplay(fd, "period_ns 20");
    $fdisplay(fd, "cmd %0d", cmd);
    $fdisplay(fd, "full %0d", (len == 0) ? 1 : 0);
    $fclose(fd);
    $finish;
  end
endmodule
