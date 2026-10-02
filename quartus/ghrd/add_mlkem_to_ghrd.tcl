# -----------------------------------------------------------------------------
# add_mlkem_to_ghrd.tcl - add the ML-KEM accelerator to Terasic's DE10-Nano
# Golden Hardware Reference Design (GHRD) so the ARM cores can use it.
#
# What it does to soc_system.qsys
#   - adds mlkem_0 (the component in ip/mlkem_accel)
#   - clocks and resets it like the GHRD's other small peripherals
#   - connects its Avalon slave to the HPS lightweight bridge
#     (h2f_lw_axi_master) at BASE, so Linux sees it at 0xFF200000 + BASE
#
# Use it (from the GHRD project folder, after copying ip/mlkem_accel there):
#   qsys-script --script=add_mlkem_to_ghrd.tcl --search-path=ip/**/*,$
#
# For the hand-written core instead: copy hw/manual to ip/mlkem_rtl in the
# GHRD folder and set CORE below to mlkem_rtl.
#
# or do the same by hand in the Platform Designer GUI (see the guide).
#
# Instance names differ between GHRD versions. The script checks that the
# ones below exist and lists what it found if they don't; edit and rerun.
# -----------------------------------------------------------------------------
package require -exact qsys 16.1

set SYSTEM_FILE soc_system.qsys
set HPS         hps_0
set LW_MASTER   hps_0.h2f_lw_axi_master
set CLOCK       clk_0.clk
set RESET       clk_0.clk_reset
set BASE        0x00040000   ;# 16 KB span: 0x40000-0x43FFF, free in the GHRD
set CORE        mlkem_accel  ;# or mlkem_rtl (hw/manual), mlkem_rtl2 (hw/manual_v2), mlkem_rtl3 (hw/manual_v3)

load_system $SYSTEM_FILE

proc need_interface {path} {
  lassign [split $path .] inst ifc
  if {[lsearch -exact [get_instances] $inst] < 0} {
    error "instance '$inst' not found; instances are: [get_instances]"
  }
  if {[lsearch -exact [get_instance_interfaces $inst] $ifc] < 0} {
    error "'$inst' has no interface '$ifc'; it has: [get_instance_interfaces $inst]"
  }
}
foreach p [list $LW_MASTER $CLOCK $RESET] { need_interface $p }

if {[lsearch -exact [get_instances] mlkem_0] >= 0} {
  puts "mlkem_0 is already in $SYSTEM_FILE - removing it and adding it again"
  remove_instance mlkem_0
}

add_instance mlkem_0 $CORE
add_connection $CLOCK mlkem_0.clock clock
add_connection $RESET mlkem_0.reset reset
add_connection $LW_MASTER mlkem_0.avalon_slave avalon
set_connection_parameter_value $LW_MASTER/mlkem_0.avalon_slave baseAddress $BASE

# The interrupt is left unconnected: the Linux program polls STATUS. To use
# it, connect mlkem_0.irq to hps_0.f2h_irq0 with a free IRQ number.

save_system
puts "added mlkem_0 at LW-bridge offset $BASE (ARM physical address [format 0x%08X [expr {0xFF200000 + $BASE}]])"
puts "now regenerate the system (Generate HDL) and compile the Quartus project"
