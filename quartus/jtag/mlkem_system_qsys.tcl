# -----------------------------------------------------------------------------
# mlkem_system_qsys.tcl - Platform Designer system for the stand-alone design.
#
#   clk_0     50 MHz clock + reset input (from the board)
#   master_0  JTAG-to-Avalon master: lets System Console on the PC read and
#             write the accelerator over the DE10-Nano's USB-Blaster II
#   mlkem_0   the ML-KEM accelerator at 0x0000: component mlkem_accel (Bambu,
#             quartus/ip/mlkem_accel) or mlkem_rtl (hand-written, hw/manual)
#
# No HPS (ARM) is involved, so this is the quickest way to see the core run
# on the board. build.tcl runs this with:
#   qsys-script --script=mlkem_system_qsys.tcl --search-path=../ip/**/*,$
# after writing the component name into mlkem_core.tcl ("set CORE ...").
# -----------------------------------------------------------------------------
package require -exact qsys 16.1

create_system mlkem_system
set_project_property DEVICE_FAMILY CYCLONEV
set_project_property DEVICE 5CSEBA6U23I7

# Clock and reset from the board. The reset input is active low (KEY0).
add_instance clk_0 clock_source
set_instance_parameter_value clk_0 clockFrequency {50000000.0}
set_instance_parameter_value clk_0 clockFrequencyKnown {1}
set_instance_parameter_value clk_0 resetSynchronousEdges {DEASSERT}

# JTAG-to-Avalon master bridge, driven from System Console
add_instance master_0 altera_jtag_avalon_master

# The accelerator (build.tcl writes mlkem_core.tcl; the default is the Bambu core)
set CORE mlkem_accel
if {[file exists mlkem_core.tcl]} { source mlkem_core.tcl }
puts "accelerator component: $CORE"
add_instance mlkem_0 $CORE

add_connection clk_0.clk master_0.clk clock
add_connection clk_0.clk mlkem_0.clock clock
add_connection clk_0.clk_reset master_0.clk_reset reset
add_connection clk_0.clk_reset mlkem_0.reset reset

add_connection master_0.master mlkem_0.avalon_slave avalon
set_connection_parameter_value master_0.master/mlkem_0.avalon_slave baseAddress {0x0000}

# The accelerator's interrupt is not used here (System Console polls STATUS);
# Platform Designer warns that mlkem_0.irq is unconnected, which is expected.

# The PQSE secure element has a tamper input and a measurement trigger output:
# exported as tamper_export and trig_export (de10_nano_pqse.v connects them to
# KEY1 and to GPIO_0[0])
if {$CORE eq "pqse_avalon"} {
  add_interface tamper conduit end
  set_interface_property tamper EXPORT_OF mlkem_0.tamper
  add_interface trig conduit end
  set_interface_property trig EXPORT_OF mlkem_0.trig
}

# Exported to the top-level Verilog as clk_clk and reset_reset_n
add_interface clk clock sink
set_interface_property clk EXPORT_OF clk_0.clk_in
add_interface reset reset sink
set_interface_property reset EXPORT_OF clk_0.clk_in_reset

save_system mlkem_system.qsys
