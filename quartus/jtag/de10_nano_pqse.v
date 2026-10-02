// -----------------------------------------------------------------------------
// de10_nano_pqse.v - top level of the stand-alone DE10-Nano design with the
// PQSE secure element (quartus_sh -t build.tcl se).
//
//   KEY0       hold to reset the system (buttons are active low)
//   KEY1       press = TAMPER: the secure element aborts, wipes every key and
//              goes to the KILLED lifecycle state (reset to recover, a chip
//              would not)
//   GPIO_0[0]  measurement trigger for the oscilloscope (JP1 pin 1; GND on
//              JP1 pin 12): high during the masked comparison window, in
//              lifecycle TEST only (quartus/jtag/pqse_tvla_capture.tcl)
//   LED0       heartbeat (about 1.5 Hz)
//   LED1       trigger (flickers while captures run)
//   LED6       KEY1 pressed
//   LED7       KEY0 pressed
// System Console drives the secure element over JTAG: quartus/jtag/pqse_test.tcl
// -----------------------------------------------------------------------------
module de10_nano_pqse (
  input  wire       FPGA_CLK1_50,
  input  wire [1:0] KEY,
  output wire [7:0] LED,
  output wire       GPIO_0_TRIG
);

  wire trig;

  mlkem_system u_system (
    .clk_clk       (FPGA_CLK1_50),
    .reset_reset_n (KEY[0]),
    .tamper_export (~KEY[1]),
    .trig_export   (trig)
  );

  assign GPIO_0_TRIG = trig;

  reg [24:0] heartbeat = 25'd0;
  always @(posedge FPGA_CLK1_50)
    heartbeat <= heartbeat + 25'd1;

  assign LED = {~KEY[0], ~KEY[1], 4'd0, trig, heartbeat[24]};

endmodule
