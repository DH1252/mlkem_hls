// -----------------------------------------------------------------------------
// de10_nano_mlkem.v - top level of the stand-alone DE10-Nano design.
//
// Only the 50 MHz clock, the two push buttons and the eight LEDs are used.
// Everything interesting is inside the Platform Designer system
// (mlkem_system: JTAG master + ML-KEM accelerator).
//
//   KEY0  hold to reset the system (the buttons are active low)
//   LED0  heartbeat, about 1.5 Hz: the clock runs and the FPGA is configured
//   LED7  on while KEY0 is held
// -----------------------------------------------------------------------------
module de10_nano_mlkem (
  input  wire       FPGA_CLK1_50,
  input  wire [1:0] KEY,
  output wire [7:0] LED
);

  mlkem_system u_system (
    .clk_clk       (FPGA_CLK1_50),
    .reset_reset_n (KEY[0])
  );

  reg [24:0] heartbeat = 25'd0;
  always @(posedge FPGA_CLK1_50)
    heartbeat <= heartbeat + 25'd1;

  assign LED = {~KEY[0], 6'd0, heartbeat[24]};

endmodule
