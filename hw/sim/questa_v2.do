# -----------------------------------------------------------------------------
# questa_v2.do - simulate the v2 core (hw/manual_v2) in the Questa / ModelSim
# GUI with waveforms. Same testbench and NIST vectors as "make sim-v2".
#
#   1. Start Questa-Intel FPGA Starter (or ModelSim-Intel FPGA Starter).
#   2. File > Change Directory...  ->  <project>/hw/sim   (this folder: the
#      testbench reads vectors/*.hex relative to it)
#   3. In the Transcript window:   do questa_v2.do
#      For the v1 core instead:    do questa_v2.do v1
#
# The transcript shows the PASS/FAIL lines and, with MLKEM_TRACE, every
# instruction the sequencer issues. All signals are logged, so any signal can
# be dragged from the Objects window into the Wave window afterwards without
# running again.
# -----------------------------------------------------------------------------
if {$argc >= 1 && $1 eq "v1"} {
  set DUT  mlkem_rtl
  set SRCS [glob ../manual/*.v]
} else {
  set DUT  mlkem_rtl2
  set SRCS [glob ../manual_v2/*.v]
}

if {[file exists work]} { vdel -lib work -all }
vlib work
eval vlog -sv +define+MLKEM_DUT=$DUT +define+MLKEM_TRACE tb_mlkem_avalon.sv $SRCS

# -onfinish stop: keep the GUI open at $finish; +acc: all signals visible
vsim -onfinish stop -voptargs=+acc work.tb_mlkem_avalon
log -r /*

set TB   /tb_mlkem_avalon
set CORE /tb_mlkem_avalon/dut/u_core

add wave -divider "Avalon bus (testbench)"
add wave $TB/clk $TB/reset $TB/read $TB/write
add wave -hex $TB/address $TB/writedata $TB/readdata
add wave $TB/irq

# v2 internals (for v1, add signals from the Objects window by hand)
if {$DUT eq "mlkem_rtl2"} {
  add wave -divider "sequencer"
  add wave $CORE/run
  add wave -unsigned $CORE/pc
  add wave -unsigned $CORE/cls
  add wave -hex $CORE/ins
  add wave $CORE/hazard $CORE/hz_h $CORE/hz_a $CORE/hz_i

  add wave -divider "engines busy (Keccak, ALU, IO)"
  add wave $CORE/h_busy $CORE/a_busy $CORE/i_busy
  add wave $CORE/bad $CORE/diff $CORE/done
  add wave -unsigned $CORE/result
}

# Optional: signal activity for the Power Analyzer (see the guide)
# vcd file v2.vcd
# vcd add -r $CORE/*

run -all
wave zoom full
