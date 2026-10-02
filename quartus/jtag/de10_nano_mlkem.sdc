# de10_nano_mlkem.sdc - timing constraints for the stand-alone design.

# 50 MHz board oscillator. This is the clock period Bambu scheduled the core
# for (--clock-period=20). If the Timing Analyzer reports negative setup
# slack, see "Timing closure" in the guide.
create_clock -name clk50 -period 20.000 [get_ports FPGA_CLK1_50]

derive_pll_clocks
derive_clock_uncertainty

# Push buttons and LEDs are slow, asynchronous board signals
set_false_path -from [get_ports {KEY[*]}] -to *
set_false_path -from * -to [get_ports {LED[*]}]
