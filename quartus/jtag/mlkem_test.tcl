# -----------------------------------------------------------------------------
# mlkem_test.tcl - System Console test of the ML-KEM accelerator on the board.
#
# The PC talks to the FPGA through the DE10-Nano's USB-Blaster II and the
# JTAG-to-Avalon master in the design, so no ARM software is needed.
#
# Run it
#   Quartus > Tools > System Debugging Tools > System Console, then in the
#   Tcl Console at the bottom:
#       cd C:/path/to/mlkem_hls/quartus/jtag
#       source mlkem_test.tcl
#   or from a shell:
#       system-console --cli --script=mlkem_test.tcl
#
# Tests
#   1. ID and PARAMS registers
#   2. NIST ACVP known answers: KeyGen, Encaps, Decaps (valid and modified
#      ciphertext), and the two input checks (bad ek, bad dk), same vectors
#      as the simulations (hw/sim/vectors)
#   3. random round trips: KeyGen -> Encaps -> Decaps must give the same
#      shared secret, and a flipped ciphertext bit must give a different one
#
# Set mlkem_base before sourcing if the accelerator is not at address 0 of
# the JTAG master, and mlkem_master to pick a master other than the first.
# -----------------------------------------------------------------------------

if {![info exists mlkem_base]}   { set mlkem_base 0x0 }
if {![info exists mlkem_master]} { set mlkem_master 0 }
if {![info exists mlkem_rounds]} { set mlkem_rounds 5 }

set here    [file normalize [file dirname [info script]]]
set vec_dir [file normalize [file join $here .. .. hw sim vectors]]

# Mailbox layout and registers (src/mlkem_accel.h, hw/rtl/mlkem_avalon.v)
array set OFF {d 0x0000 z 0x0020 m 0x0040 ss 0x0060 ek 0x0100 dk 0x0800 ct 0x1800}
array set REG {ctrl 0x2000 status 0x2004 result 0x2008 cycles 0x200C id 0x2010 params 0x2014 irq_en 0x2018}
set EK 1184
set DK 2400
set CT 1088
set CLOCK_MHZ 50.0

# --- connect to the JTAG master ----------------------------------------------
set masters [get_service_paths master]
if {[llength $masters] == 0} {
  error "no JTAG master found - is the board connected and the .sof programmed?"
}
puts "masters found:"
foreach m $masters { puts "  $m" }
set mpath [lindex $masters $mlkem_master]
set jm [claim_service master $mpath mlkem_test]
puts "using $mpath\n"

# --- bus helpers ---------------------------------------------------------------
proc addr {off} {
  global mlkem_base
  return [format 0x%08X [expr {$mlkem_base + $off}]]
}
proc wr32 {off value} {
  global jm
  master_write_32 $jm [addr $off] [list $value]
}
proc rd32 {off} {
  global jm
  return [expr {[lindex [master_read_32 $jm [addr $off] 1] 0] + 0}]
}

# Byte lists <-> little-endian 32-bit words (all sizes are multiples of 4)
proc put_bytes {off bytes} {
  global jm
  set words {}
  for {set i 0} {$i < [llength $bytes]} {incr i 4} {
    set w 0
    for {set b 0} {$b < 4} {incr b} {
      set w [expr {$w | ([lindex $bytes [expr {$i + $b}]] << (8 * $b))}]
    }
    lappend words [format 0x%08X $w]
  }
  for {set i 0} {$i < [llength $words]} {incr i 256} {
    master_write_32 $jm [addr [expr {$off + 4 * $i}]] [lrange $words $i [expr {$i + 255}]]
  }
}
proc get_bytes {off n} {
  global jm
  set bytes {}
  foreach w [master_read_32 $jm [addr $off] [expr {$n / 4}]] {
    for {set b 0} {$b < 4} {incr b} {
      lappend bytes [expr {($w >> (8 * $b)) & 0xFF}]
    }
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

proc random_bytes {n} {
  # Tcl's rand() is NOT a cryptographic generator: fine for a test,
  # never for real keys.
  set r {}
  for {set i 0} {$i < $n} {incr i} { lappend r [expr {int(rand() * 256)}] }
  return $r
}

# Start an operation, poll until DONE, clear DONE. Returns {result cycles}.
proc run_op {op} {
  global REG
  wr32 $REG(ctrl) $op
  set t0 [clock milliseconds]
  while {([rd32 $REG(status)] & 2) == 0} {
    if {[clock milliseconds] - $t0 > 5000} { error "timeout waiting for DONE (op $op)" }
  }
  set result [rd32 $REG(result)]
  set cycles [rd32 $REG(cycles)]
  wr32 $REG(status) 2
  return [list $result $cycles]
}

set errors 0
proc check {what ok {cycles ""}} {
  global errors CLOCK_MHZ
  set extra ""
  if {$cycles ne ""} {
    set extra [format " (%d cycles = %.2f ms at %.0f MHz)" $cycles [expr {$cycles / ($CLOCK_MHZ * 1000.0)}] $CLOCK_MHZ]
  }
  if {$ok} { puts "\[PASS\] $what$extra" } else { puts "\[FAIL\] $what$extra"; incr errors }
}

# Operations on byte lists
proc keygen {d z} {
  global OFF EK DK
  put_bytes $OFF(d) $d
  put_bytes $OFF(z) $z
  lassign [run_op 1] r c
  return [list $r $c [get_bytes $OFF(ek) $EK] [get_bytes $OFF(dk) $DK]]
}
proc encaps {ek m} {
  global OFF CT
  put_bytes $OFF(ek) $ek
  put_bytes $OFF(m) $m
  lassign [run_op 2] r c
  return [list $r $c [get_bytes $OFF(ct) $CT] [get_bytes $OFF(ss) 32]]
}
proc decaps {dk ct} {
  global OFF
  put_bytes $OFF(dk) $dk
  put_bytes $OFF(ct) $ct
  lassign [run_op 3] r c
  return [list $r $c [get_bytes $OFF(ss) 32]]
}

# --- 1. identification ---------------------------------------------------------
set id [rd32 $REG(id)]
set k  [rd32 $REG(params)]
check [format "ID register = 0x%08X (expect 0x4D4C4B4D), k = %d" $id $k] [expr {$id == 0x4D4C4B4D && $k == 3}]
if {$id != 0x4D4C4B4D} {
  close_service master $jm
  error "accelerator not found at [addr 0] - check mlkem_base"
}

# --- 2. NIST known answers -----------------------------------------------------
lassign [keygen [load_hex kg_d] [load_hex kg_z]] r c ek dk
check "KeyGen: ek and dk match NIST" [expr {$r == 0 && $ek eq [load_hex kg_ek] && $dk eq [load_hex kg_dk]}] $c

lassign [encaps [load_hex en_ek] [load_hex en_m]] r c ct ss
check "Encaps: ciphertext and shared secret match NIST" [expr {$r == 0 && $ct eq [load_hex en_c] && $ss eq [load_hex en_k]}] $c

lassign [decaps [load_hex de0_dk] [load_hex de0_c]] r c ss
check "Decaps (valid ciphertext): shared secret matches NIST" [expr {$r == 0 && $ss eq [load_hex de0_k]}] $c

lassign [decaps [load_hex de1_dk] [load_hex de1_c]] r c ss
check "Decaps (modified ciphertext): implicit-rejection secret matches NIST" [expr {$r == 0 && $ss eq [load_hex de1_k]}] $c

lassign [encaps [load_hex bad_ek] [load_hex en_m]] r c ct ss
check "Encaps rejects an ek that fails the modulus check (status 1)" [expr {$r == 1}]

lassign [decaps [load_hex bad_dk] [load_hex de0_c]] r c ss
check "Decaps rejects a dk that fails the hash check (status 1)" [expr {$r == 1}]

# --- 3. random round trips -----------------------------------------------------
expr {srand([clock clicks])}
for {set i 1} {$i <= $mlkem_rounds} {incr i} {
  lassign [keygen [random_bytes 32] [random_bytes 32]] r1 c1 ek dk
  lassign [encaps $ek [random_bytes 32]] r2 c2 ct ss_enc
  lassign [decaps $dk $ct] r3 c3 ss_dec
  # flip one bit of the ciphertext: Decaps must return a different secret
  set pos [expr {int(rand() * $CT)}]
  set bad [lreplace $ct $pos $pos [expr {[lindex $ct $pos] ^ 1}]]
  lassign [decaps $dk $bad] r4 c4 ss_bad
  check "round trip $i: Encaps and Decaps agree, tampered ciphertext rejected" \
        [expr {$r1 == 0 && $r2 == 0 && $r3 == 0 && $r4 == 0 && $ss_enc eq $ss_dec && $ss_bad ne $ss_enc}]
}

# Keys and secrets stay in the mailbox after an operation: wipe it
master_write_32 $jm [addr 0] [lrepeat 2048 0]

close_service master $jm
puts "----------------------------------------------------------------"
if {$errors == 0} { puts "ALL TESTS PASSED" } else { puts "$errors TEST(S) FAILED" }
