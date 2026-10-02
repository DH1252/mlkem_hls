# -----------------------------------------------------------------------------
# questa_v3.do - simulate the v3 core (hw/manual_v3) in the Questa / ModelSim
# GUI with waveforms. Same testbench and NIST vectors as "make sim-v3".
#
#   1. Start Questa-Intel FPGA Starter (or ModelSim-Intel FPGA Starter).
#   2. File > Change Directory...  ->  <project>/hw/sim
#   3. In the Transcript window:   do questa_v3.do
#
# The transcript shows the PASS/FAIL lines, every issued instruction
# (MLKEM_TRACE) with the busy clocks of each engine at the end of each
# operation, and "NTT CHECK FAIL" if the NTT engine ever reads a word before
# its new value is written (MLKEM_SIM_CHECK). All signals are logged.
# -----------------------------------------------------------------------------
if {[file exists work]} { vdel -lib work -all }
vlib work
eval vlog -sv +define+MLKEM_DUT=mlkem_rtl3 +define+MLKEM_TRACE +define+MLKEM_SIM_CHECK \
     tb_mlkem_avalon.sv [glob ../manual_v3/*.v]

vsim -onfinish stop -voptargs=+acc work.tb_mlkem_avalon
log -r /*

set TB   /tb_mlkem_avalon
set CORE /tb_mlkem_avalon/dut/u_core

add wave -divider "Avalon bus (testbench)"
add wave $TB/clk $TB/reset $TB/read $TB/write
add wave -hex $TB/address $TB/writedata $TB/readdata
add wave $TB/irq

add wave -divider "sequencer"
add wave $CORE/run
add wave -unsigned $CORE/pc
add wave -unsigned $CORE/cls
add wave -hex $CORE/ins
add wave $CORE/hazard $CORE/hz_h $CORE/hz_n $CORE/hz_p $CORE/hz_i

add wave -divider "engines busy (Keccak, NTT, PWM, IO)"
add wave $CORE/h_busy $CORE/n_busy $CORE/p_busy $CORE/i_busy
add wave $CORE/bad $CORE/diff $CORE/done
add wave -unsigned $CORE/result

add wave -divider "NTT engine"
add wave -unsigned $CORE/u_ntt/ps $CORE/u_ntt/cnt
add wave -hex $CORE/u_ntt/vld

run -all
wave zoom full
