# -----------------------------------------------------------------------------
# pqse_power.tcl - OpenSTA power and timing estimate of the PQSE secure element
# on SkyWater 130 nm (sky130_fd_sc_hd). Run by "make se-power", which first
# maps the design with Yosys:
#
#   make se-power SKY130_LIB=<path>/sky130_fd_sc_hd__tt_025C_1v80.lib
#       vectorless: every net toggles with probability ACT per clock (default
#       0.1, a common first guess for a datapath; try 0.05 and 0.2 to see the
#       range)
#   make se-power-vcd SKY130_LIB=... [GL_CMD=1] [GL_START=20000] [GL_LEN=2000]
#       activity from a gate-level simulation of the mapped netlist (Verilator,
#       cell models generated from the Liberty file, hw/sim/tb_pqse_gate.sv):
#       GL_LEN clocks of command GL_CMD, from GL_START clocks into it
#   make se-power SKY130_LIB=... VCD=<dump.vcd> SCOPE=<tb>/<dut instance>
#       activity from any other VCD of the same netlist (the net names must
#       match it)
#
# Environment: SKY130_LIB, NETLIST, ACT, VCD, SCOPE, PERIOD_NS (default 20)
#
# What the numbers mean: the memories (polynomial RAM 2 x 1024 x 25, I/O
# buffer 512 x 64, seed registers 2 x 64 x 65) are synthesized as flip-flops
# here, which a chip would build as SRAM macros (OpenRAM / sky130 SRAM) with a
# fraction of the area and of the clock power. Read the "Sequential" group as
# an upper bound; the combinational group is the datapath.
# -----------------------------------------------------------------------------
proc env_or {name dflt} {
  if {[info exists ::env($name)] && $::env($name) ne ""} { return $::env($name) }
  return $dflt
}

set lib     [env_or SKY130_LIB ""]
set netlist [env_or NETLIST build/sepower/pqse_top_sky130.v]
set period  [env_or PERIOD_NS 20.0]
set act     [env_or ACT 0.1]
set vcd     [env_or VCD ""]
set scope   [env_or SCOPE ""]
if {$lib eq ""} { puts "set SKY130_LIB"; exit 1 }

read_liberty $lib
read_verilog $netlist
link_design pqse_top

create_clock -name clk -period $period [get_ports clk]
set_input_delay  0.0 -clock clk [delete_from_list [all_inputs] [get_ports clk]]
set_output_delay 0.0 -clock clk [all_outputs]
set_input_transition 0.1 [all_inputs]
set_load 0.01 [all_outputs]

if {$vcd ne ""} {
  puts "activity: $vcd (scope $scope)"
  read_vcd -scope $scope $vcd
  # how many nets / pins the VCD annotated (0: SCOPE does not match the VCD)
  catch {report_activity_annotation}
} else {
  puts "activity: vectorless, $act toggles per clock on every net"
  set_power_activity -global -activity $act -duty 0.5
  set_power_activity -input -activity $act -duty 0.5
}

puts "\nPQSE secure element, sky130_fd_sc_hd, clock period $period ns"
puts "==================== power ===================="
report_power -digits 4
puts "==================== timing (slowest path) ===================="
report_checks -path_delay max -digits 3
report_wns
report_tns
