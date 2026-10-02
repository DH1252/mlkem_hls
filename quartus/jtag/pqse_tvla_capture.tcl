# -----------------------------------------------------------------------------
# pqse_tvla_capture.tcl - System Console: run the masked Decaps once per
# ciphertext of a TVLA input file, so an oscilloscope can capture one power /
# EM trace per run (board-level TVLA, fixed-vs-random m, first order).
#
#   1. on the PC:   python3 scripts/pqse_tvla.py gen 2000 tvla_in.txt --seed 1
#   2. the board:   quartus_sh -t build.tcl se, program the .sof (lifecycle
#                   TEST after reset: the trigger pin only works in TEST)
#   3. the scope:   channel 1 = the measurement (EM probe over the FPGA, or a
#                   shunt in the core supply), channel 2 / EXT = the trigger,
#                   GPIO_0[0] (JP1 pin 1, GND on JP1 pin 12), rising edge;
#                   segmented / sequence mode with one segment per Decaps
#                   (the trigger stays high for the whole masked window, about
#                   200k clocks = 4 ms at 50 MHz)
#   4. System Console:
#        cd C:/path/to/mlkem_hls/quartus/jtag
#        set pqse_tvla_in C:/path/to/tvla_in.txt
#        source pqse_tvla_capture.tcl
#   5. export the segments in capture order as an N x S array (.npy) or one
#      trace per line (.csv), then:
#        python3 scripts/pqse_tvla.py board traces.npy tvla_in.txt
#      and for TVLA's two-set rule a second capture with --seed 2, then
#        python3 scripts/pqse_tvla.py confirm tvla_board_t.txt tvla_board_t2.txt
#
# Optional, set before sourcing:
#   set pqse_tvla_in   tvla_in.txt   the gen file (default: ./tvla_in.txt)
#   set pqse_tvla_gap  20            ms to wait after each run (scope re-arm)
#   set pqse_tvla_hide 0             1: hiding on (shuffling, dummy clocks):
#                                    the traces no longer line up; use
#                                    pqse_tvla.py board --align, and expect a
#                                    lower t than with masking alone
#
# The NIST KeyGen dk (hw/sim/vectors/kg_dk.hex) is imported first, so every
# ciphertext of the gen file decapsulates under the key it was made for.
# -----------------------------------------------------------------------------
if {![info exists pqse_base]}              { set pqse_base 0x0 }
if {![info exists pqse_master]}            { set pqse_master 0 }
if {![info exists pqse_tvla_in]}           { set pqse_tvla_in tvla_in.txt }
if {![info exists pqse_tvla_gap]}          { set pqse_tvla_gap 20 }
if {![info exists pqse_tvla_hide]}         { set pqse_tvla_hide 0 }

set here    [file normalize [file dirname [info script]]]
set vec_dir [file normalize [file join $here .. .. hw sim vectors]]

array set LANE {ekown 0 xin 164 k 448 injz 456 injh 464}
array set REG  {id 0x400 version 0x401 ctrl 0x402 status 0x403 cycles 0x404 lifecycle 0x405 config 0x406}
set DECAPS 3
set IMPORT 4

set masters [get_service_paths master]
if {[llength $masters] == 0} { error "no JTAG master found - is the board connected and programmed?" }
set jm [claim_service master [lindex $masters $pqse_master] pqse_tvla]

proc baddr {byte} { global pqse_base; return [format 0x%08X [expr {$pqse_base + $byte}]] }
proc wreg {w v} { global jm; master_write_32 $jm [baddr [expr {4 * $w}]] [list $v] }
proc rreg {w}   { global jm; return [expr {[lindex [master_read_32 $jm [baddr [expr {4 * $w}]] 1] 0] + 0}] }
proc put {lane bytes} {
  global jm
  set words {}
  for {set i 0} {$i < [llength $bytes]} {incr i 4} {
    set w 0
    for {set b 0} {$b < 4} {incr b} {
      set v [lindex $bytes [expr {$i + $b}]]
      if {$v eq ""} { set v 0 }
      set w [expr {$w | ($v << (8 * $b))}]
    }
    lappend words [format 0x%08X $w]
  }
  for {set i 0} {$i < [llength $words]} {incr i 256} {
    master_write_32 $jm [baddr [expr {8 * $lane + 4 * $i}]] [lrange $words $i [expr {$i + 255}]]
  }
}
proc get {lane n} {
  global jm
  set bytes {}
  foreach w [master_read_32 $jm [baddr [expr {8 * $lane}]] [expr {$n / 4}]] {
    for {set b 0} {$b < 4} {incr b} { lappend bytes [expr {($w >> (8 * $b)) & 0xFF}] }
  }
  return $bytes
}
proc load_hex {name} {
  global vec_dir
  set fh [open [file join $vec_dir $name.hex] r]
  set bytes {}
  foreach line [split [read $fh] "\n"] {
    set line [string trim $line]
    if {$line ne ""} { scan $line %x v; lappend bytes $v }
  }
  close $fh
  return $bytes
}
proc run {cmd} {
  global REG
  wreg $REG(ctrl) $cmd
  set t0 [clock milliseconds]
  while {1} {
    set st [rreg $REG(status)]
    if {$st & 2} break
    if {[clock milliseconds] - $t0 > 20000} { error "timeout (command $cmd)" }
  }
  wreg $REG(status) 2
  return [expr {($st >> 8) & 0xFF}]
}

# ---- set up: TEST lifecycle, NIST dk imported -----------------------------------------
while {[rreg $REG(status)] & 1} { after 10 }
if {[rreg $REG(lifecycle)] != 0} {
  error "the device is not in lifecycle TEST (reset the board with KEY0): the trigger pin is off otherwise"
}
set dk [load_hex kg_dk]
put $LANE(xin)   [lrange $dk 0 1151]
put $LANE(ekown) [lrange $dk 1152 2335]
put $LANE(injh)  [lrange $dk 2336 2367]
put $LANE(injz)  [lrange $dk 2368 2399]
if {[run $IMPORT] != 0} { error "import of the NIST dk failed" }
wreg $REG(config) $pqse_tvla_hide
puts "device ready: ID [format 0x%08X [rreg $REG(id)]], version [format 0x%08X [rreg $REG(version)]], hiding $pqse_tvla_hide"

# ---- the captures ---------------------------------------------------------------------
set fh [open $pqse_tvla_in r]
set n [string trim [gets $fh]]
puts "running $n Decaps from $pqse_tvla_in (one trigger pulse each, $pqse_tvla_gap ms apart)"
set ord [open tvla_capture_order.txt w]
set t0 [clock seconds]
for {set k 0} {$k < $n} {incr k} {
  set line [gets $fh]
  set f [split [string trim $line]]
  set cls [lindex $f 0]
  set ct {}
  foreach h [lrange $f 1 end] { scan $h %x v; lappend ct $v }
  if {[llength $ct] != 1088} { error "line [expr {$k + 2}] of $pqse_tvla_in: [llength $ct] bytes, not 1088" }
  put $LANE(xin) $ct
  set r [run $DECAPS]
  if {$r != 0} { puts "warning: Decaps $k returned $r" }
  puts $ord "$k $cls $r"
  after $pqse_tvla_gap
  if {($k + 1) % 100 == 0} {
    set dt [expr {[clock seconds] - $t0}]
    puts "  [expr {$k + 1}] / $n  ($dt s)"
  }
}
close $fh
close $ord
wreg $REG(config) 1
puts "done: $n Decaps; classes in capture order: tvla_capture_order.txt"
puts "next: export the $n scope segments in order, then"
puts "      python3 scripts/pqse_tvla.py board traces.npy $pqse_tvla_in"
close_service master $jm
