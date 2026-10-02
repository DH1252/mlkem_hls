# -----------------------------------------------------------------------------
# pqse_power.tcl - OpenSTA power and timing estimate of the PQSE secure element
# on SkyWater 130 nm (sky130_fd_sc_hd). Run by "make se-power", which first
# maps the design with Yosys:
#
#   make se-power SKY130_LIB=<path>/sky130_fd_sc_hd__tt_025C_1v80.lib
#       vectorless: every net toggles with probability ACT per clock (default
#       0.1, a common first guess for a datapath; try 0.05 and 0.2 to see the
#       range)
#   make se-power-vcd SKY130_LIB=... [GL_CMD=1] [GL_LEN=0] [GL_FMT=saif]
#       activity from a gate-level simulation of the mapped netlist (Verilator,
#       cell models generated from the Liberty file, hw/sim/tb_pqse_gate.sv):
#       the whole command GL_CMD (or GL_LEN clocks from GL_START), then energy
#       per command (scripts/power/pqse_energy.py)
#   make se-power SKY130_LIB=... VCD=<dump.vcd|.saif> SCOPE=<tb>/<dut instance>
#       activity from any other VCD / SAIF of the same netlist: it must hold
#       the cell instances' pins (OpenSTA annotates pins, <instance>/<pin>
#       below SCOPE, not net names); a name ending in .saif is read as SAIF
#
# Environment: SKY130_LIB, RAM_LIB, NETLIST, ACT, VCD, SCOPE, PERIOD_NS (20)
#
# What the numbers mean: with RAM_MACRO=0 the memories are synthesized as
# flip-flops, which a chip would build as SRAM macros with a fraction of the
# area and of the clock power: read the "Sequential" group as an upper bound.
# With RAM_MACRO=1 they are black-box macros without power (the logic only;
# make se-power-vcd adds their energy from access counts). Clock gating cells
# (CLOCKGATE=1) are in the "Clock" group. The clock net is the bare net (no
# clock tree: its buffers would add to "Clock").
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
# RAM_MACRO=1: the RAM macro stubs (no power: the report covers the logic only)
set ramlib  [env_or RAM_LIB ""]
if {$ramlib ne ""} {
  read_liberty $ramlib
  puts "RAMs as SRAM macros ($ramlib): their power is NOT included"
}
read_verilog $netlist
link_design pqse_top

create_clock -name clk -period $period [get_ports clk]
set_input_delay  0.0 -clock clk [delete_from_list [all_inputs] [get_ports clk]]
set_output_delay 0.0 -clock clk [all_outputs]
set_input_transition 0.1 [all_inputs]
set_load 0.01 [all_outputs]

if {$vcd ne ""} {
  if {[regexp {\.saif(\.gz)?$} $vcd]} {
    puts "activity: SAIF $vcd (scope $scope)"
    read_saif -scope $scope $vcd
  } else {
    puts "activity: VCD $vcd (scope $scope)"
    read_vcd -scope $scope $vcd
  }
  # how many pins the dump annotated ("unannotated" should be a small part:
  # mostly constant tie cells; nearly all unannotated: SCOPE does not match the
  # dump, or it holds nets only - OpenSTA then propagates from the inputs)
  puts "==================== activity annotation ===================="
  catch {report_activity_annotation}
} else {
  puts "activity: vectorless, $act toggles per clock on every net"
  set_power_activity -global -activity $act -duty 0.5
  set_power_activity -input -activity $act -duty 0.5
}

puts "\nPQSE secure element, sky130_fd_sc_hd, clock period $period ns"
puts "==================== power ===================="
report_power -digits 4
puts "==================== highest-power instances ===================="
catch {report_power -highest_power_instances 25 -digits 4}
puts "==================== timing (slowest path) ===================="
# fanout, load capacitance and slew per stage: a stage with a large fanout and
# a slow transition is a net a real flow would buffer (placement-based repair)
report_checks -path_delay max -digits 3 -fields {fanout cap slew}
report_wns
report_tns
