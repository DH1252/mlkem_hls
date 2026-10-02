# -----------------------------------------------------------------------------
# build.tcl - build the stand-alone DE10-Nano design from scratch.
#
#   cd quartus/jtag
#   quartus_sh -t build.tcl            (all steps)
#   quartus_sh -t build.tcl nocompile  (stop after creating the project, e.g.
#                                       to compile from the Quartus GUI)
#   quartus_sh -t build.tcl rtl        (use the hand-written RTL core in
#                                       hw/manual instead of the Bambu core;
#                                       combines with nocompile)
#   quartus_sh -t build.tcl rtl2       (the v2 hand-written core, hw/manual_v2)
#   quartus_sh -t build.tcl rtl3       (the v3 hand-written core, hw/manual_v3)
#   quartus_sh -t build.tcl se         (the PQSE secure element, hw/se: top
#                                       de10_nano_pqse.v, KEY1 = tamper,
#                                       ring-oscillator TRNG and PUF)
#
# Steps
#   1. copy the Bambu *.mem files into this (the project) folder, where
#      Quartus looks for the files named in $readmemb (none for "rtl")
#   2. create the Platform Designer system  (qsys-script)
#   3. generate its Verilog                  (qsys-generate)
#   4. create the Quartus project: device, pins, files, constraints
#   5. compile: synthesis, fitter, assembler (.sof), timing analysis
#
# Works with Quartus Prime Lite or Standard (Cyclone V is supported by the
# free Lite edition) on Windows or Linux.
# -----------------------------------------------------------------------------
package require ::quartus::project
package require ::quartus::flow

set PROJECT de10_nano_mlkem
set SYSTEM  mlkem_system
set FAMILY  "Cyclone V"
set DEVICE  5CSEBA6U23I7

# which accelerator: the Bambu component (default) or a hand-written one
set TOP de10_nano_mlkem
if {[lsearch -exact $quartus(args) se] >= 0} {
  set CORE    pqse_avalon
  set IP_DIR  ../../hw/se
  set TOP     de10_nano_pqse
} elseif {[lsearch -exact $quartus(args) rtl3] >= 0} {
  set CORE    mlkem_rtl3
  set IP_DIR  ../../hw/manual_v3
} elseif {[lsearch -exact $quartus(args) rtl2] >= 0} {
  set CORE    mlkem_rtl2
  set IP_DIR  ../../hw/manual_v2
} elseif {[lsearch -exact $quartus(args) rtl] >= 0} {
  set CORE    mlkem_rtl
  set IP_DIR  ../../hw/manual
} else {
  set CORE    mlkem_accel
  set IP_DIR  ../ip/mlkem_accel
}

set here [file normalize [file dirname [info script]]]
# Windows Quartus cannot work in a network (UNC) folder such as the WSL file
# system (\\wsl.localhost\...): copy the project to a local drive first.
if {[string match "//*" $here]} {
  puts "ERROR: the project is in a network folder: $here"
  puts "Windows Quartus cannot build there. Copy the project to a local drive, e.g. from WSL:"
  puts "    rsync -a --exclude build ~/mlkem_hls/ /mnt/c/mlkem_hls/"
  puts "then run:  cd /d C:\\mlkem_hls\\quartus\\jtag  and  quartus_sh -t build.tcl rtl2"
  exit 1
}
cd $here

# --- helpers -----------------------------------------------------------------
# Platform Designer's command-line tools live in <quartus>/sopc_builder/bin,
# which is usually not on the PATH.
proc find_tool {name} {
  set dirs {}
  if {[info exists ::env(QUARTUS_ROOTDIR)]} {
    lappend dirs [file join $::env(QUARTUS_ROOTDIR) sopc_builder bin]
  }
  lappend dirs [file join $::quartus(binpath) .. sopc_builder bin]
  foreach d $dirs {
    foreach ext {"" .exe} {
      set f [file normalize [file join $d $name$ext]]
      if {[file exists $f]} { return $f }
    }
  }
  set f [auto_execok $name]
  if {$f ne ""} { return $f }
  error "cannot find $name - add <quartus install>/quartus/sopc_builder/bin to PATH"
}

proc run {args} {
  puts "\n>>> [join $args]"
  exec {*}$args >@ stdout 2>@ stderr
}

proc show_file {path} {
  if {[file exists $path]} {
    set fh [open $path r]
    puts [read $fh]
    close $fh
  }
}

# --- 1. memory initialisation files ------------------------------------------
if {![file exists $IP_DIR/${CORE}_hw.tcl]} {
  if {$CORE eq "mlkem_accel"} {
    error "$IP_DIR is missing - run 'make ip' (scripts/package_ip.py) first"
  }
  error "$IP_DIR/${CORE}_hw.tcl is missing"
}
set mems [glob -nocomplain -directory $IP_DIR *.mem]
foreach f [glob -nocomplain *.mem] { file delete $f }
foreach f $mems { file copy -force $f . }
puts "accelerator: $CORE ($IP_DIR); copied [llength $mems] .mem files into [pwd]"

# --- 2 + 3. Platform Designer system -----------------------------------------
# mlkem_system_qsys.tcl reads the component name from mlkem_core.tcl
set fh [open mlkem_core.tcl w]
puts $fh "set CORE $CORE"
close $fh
set search "--search-path=$IP_DIR/**/*,\$"
run [find_tool qsys-script] --script=mlkem_system_qsys.tcl $search
run [find_tool qsys-generate] $SYSTEM.qsys --synthesis=VERILOG $search

# --- 4. Quartus project ------------------------------------------------------
project_new -overwrite $PROJECT

set_global_assignment -name FAMILY $FAMILY
set_global_assignment -name DEVICE $DEVICE
set_global_assignment -name TOP_LEVEL_ENTITY $TOP
set_global_assignment -name PROJECT_OUTPUT_DIRECTORY output_files
set_global_assignment -name MIN_CORE_JUNCTION_TEMP "-40"
set_global_assignment -name MAX_CORE_JUNCTION_TEMP 100

set_global_assignment -name VERILOG_FILE $TOP.v
if {$CORE eq "pqse_avalon"} {
  # ring oscillators for the TRNG and the SRAM-cell latch PUF (instead of the
  # simulation models)
  set_global_assignment -name VERILOG_MACRO "PQSE_FPGA=1"
  set_global_assignment -name VERILOG_MACRO "PQSE_PUF_LATCH=1"
}
set_global_assignment -name QIP_FILE $SYSTEM/synthesis/$SYSTEM.qip
set_global_assignment -name SDC_FILE $PROJECT.sdc

# Board pins (DE10-Nano user manual / Intel's DE10-Nano reference design)
set_location_assignment PIN_V11  -to FPGA_CLK1_50
set_location_assignment PIN_AH17 -to {KEY[0]}
set_location_assignment PIN_AH16 -to {KEY[1]}
set_location_assignment PIN_W15  -to {LED[0]}
set_location_assignment PIN_AA24 -to {LED[1]}
set_location_assignment PIN_V16  -to {LED[2]}
set_location_assignment PIN_V15  -to {LED[3]}
set_location_assignment PIN_AF26 -to {LED[4]}
set_location_assignment PIN_AE26 -to {LED[5]}
set_location_assignment PIN_Y16  -to {LED[6]}
set_location_assignment PIN_AA23 -to {LED[7]}
foreach pin {FPGA_CLK1_50 KEY[0] KEY[1] LED[0] LED[1] LED[2] LED[3] LED[4] LED[5] LED[6] LED[7]} {
  set_instance_assignment -name IO_STANDARD "3.3-V LVTTL" -to $pin
}
if {$CORE eq "pqse_avalon"} {
  # measurement trigger on GPIO_0[0] (header JP1 pin 1; check the pin against
  # the DE10-Nano user manual, table "Pin assignments of GPIO_0")
  set_location_assignment PIN_V12 -to GPIO_0_TRIG
  set_instance_assignment -name IO_STANDARD "3.3-V LVTTL" -to GPIO_0_TRIG
}

export_assignments
puts "\nproject $PROJECT.qpf created"

if {[lsearch -exact $quartus(args) nocompile] >= 0} {
  project_close
  puts "stopping before compilation (nocompile) - open $PROJECT.qpf in Quartus"
  exit 0
}

# --- 5. compile ---------------------------------------------------------------
if {[catch {execute_flow -compile} err]} {
  project_close
  puts "\nCOMPILATION FAILED: $err"
  puts "see output_files/$PROJECT.map.rpt and output_files/$PROJECT.fit.rpt"
  exit 1
}
project_close

puts "\n==================== resource use ===================="
show_file output_files/$PROJECT.fit.summary
puts "==================== timing ==========================="
show_file output_files/$PROJECT.sta.summary
puts "Look for 'Slack' under the Setup lines above: it must be positive."
puts "Bitstream: output_files/$PROJECT.sof"
