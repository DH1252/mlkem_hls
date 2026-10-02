# -----------------------------------------------------------------------------
# pqse_test.tcl - System Console demo / test of the PQSE secure element on the
# DE10-Nano (quartus_sh -t build.tcl se, then program the .sof).
#
#   Quartus > Tools > System Debugging Tools > System Console:
#       cd C:/path/to/mlkem_hls/quartus/jtag
#       source pqse_test.tcl
#   or:  system-console --cli --script=pqse_test.tcl
#
# Optional, set before sourcing:
#   set pqse_puf_dumps 20     PUFRAW dumps written to puf_raw.txt   (default 4)
#   set pqse_trng_dumps 120   TRNGRAW dumps written to trng_raw.txt (default 4;
#                             120 dumps = 1M bits for an SP 800-90B assessment)
#   then: python3 scripts/pqse_puf_stats.py --puf puf_raw.txt --trng trng_raw.txt
#   (run the script on several boards and pass every puf_raw.txt for the
#    inter-device distance)
#
# Steps
#   1. ID, version, lifecycle TEST after the power-on wipe
#   2. NIST known answers: KeyGen (injected d, z), Encaps (injected m),
#      Import + masked Decaps (valid and modified ciphertext)
#   3. secure-element flow: PUF enroll (RM(1,5) helper data + key check
#      value), KeyGen with TRNG seeds + wrap, Encaps to the card's ek, masked
#      Decaps, same K; secure messaging (KMAC256; SEAL as initiator with
#      lengths 128 / 100 / 1, OPEN as responder; out-of-order delivery inside
#      the window accepted, replayed and modified messages and bad lengths
#      rejected); zeroize; unwrap gives the same ek back
#   (side-channel captures with an oscilloscope: pqse_tvla_capture.tcl)
#   4. raw PUF / TRNG dumps (TEST only) -> puf_raw.txt, trng_raw.txt
#   5. lifecycle USER: key import refused, K never readable, SEAL / OPEN still
#      work with the session key kept inside
#   6. tamper: press KEY1 when asked -> zeroized, KILLED
# -----------------------------------------------------------------------------
if {![info exists pqse_base]}       { set pqse_base 0x0 }
if {![info exists pqse_master]}     { set pqse_master 0 }
if {![info exists pqse_puf_dumps]}  { set pqse_puf_dumps 4 }
if {![info exists pqse_trng_dumps]} { set pqse_trng_dumps 4 }

set here    [file normalize [file dirname [info script]]]
set vec_dir [file normalize [file join $here .. .. hw sim vectors]]
set CLOCK_MHZ 50.0

# lane bases (hw/se/pqse_defs.vh); byte address = 8 * lane
array set LANE {ekown 0 help 148 xin 164 xout 312 k 448 injd 452 injz 456 injm 460 injh 464
                blob 468 sm 484 smmsg 488 smtag 504}
array set REG  {id 0x400 version 0x401 ctrl 0x402 status 0x403 cycles 0x404 lifecycle 0x405 config 0x406}
array set CMD  {keygen 1 encaps 2 decaps 3 import 4 enroll 5 kgwrap 6 unwrap 7 zeroize 8
                seal 9 open 10 pufraw 11 trngraw 12}
set EK 1184
set CT 1088
set HELP 128
set RAWB 120
set BLOB 112
set SM 192

set masters [get_service_paths master]
if {[llength $masters] == 0} { error "no JTAG master found - is the board connected and programmed?" }
set jm [claim_service master [lindex $masters $pqse_master] pqse_test]

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
proc hexline {bytes} {
  set s ""
  foreach b $bytes { append s [format %02x $b] }
  return $s
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
proc wait_idle {} {
  global REG
  set t0 [clock milliseconds]
  while {[rreg $REG(status)] & 1} {
    if {[clock milliseconds] - $t0 > 20000} { error "timeout waiting for idle" }
  }
}
# run a command; returns {result cycles}
proc run {cmd {inj 0}} {
  global REG
  wreg $REG(ctrl) [expr {$cmd | ($inj << 8)}]
  set t0 [clock milliseconds]
  while {1} {
    set st [rreg $REG(status)]
    if {$st & 2} break
    if {[clock milliseconds] - $t0 > 20000} { error "timeout (command $cmd)" }
  }
  set cyc [rreg $REG(cycles)]
  wreg $REG(status) 2
  return [list [expr {($st >> 8) & 0xFF}] $cyc]
}
set errors 0
proc check {what ok {cyc ""}} {
  global errors CLOCK_MHZ
  set x ""
  if {$cyc ne ""} { set x [format " (%d cycles = %.2f ms at %.0f MHz)" $cyc [expr {$cyc / ($CLOCK_MHZ * 1000.0)}] $CLOCK_MHZ] }
  if {$ok} { puts "\[PASS\] $what$x" } else { puts "\[FAIL\] $what$x"; incr errors }
}
proc import_dk {dk} {
  global LANE CMD
  put $LANE(xin)   [lrange $dk 0 1151]
  put $LANE(ekown) [lrange $dk 1152 2335]
  put $LANE(injh)  [lrange $dk 2336 2367]
  put $LANE(injz)  [lrange $dk 2368 2399]
  return [run $CMD(import)]
}
proc test_msg {seed} {
  set m {}
  for {set i 0} {$i < 128} {incr i} { lappend m [expr {($i * 37 + $seed * 11 + 5) & 0xFF}] }
  return $m
}
# SEAL a message of len bytes (header lane 1 = length); returns {result sealed}
proc seal {msg len} {
  global LANE CMD SM
  put $LANE(smmsg) $msg
  put [expr {$LANE(sm) + 1}] [list $len 0 0 0 0 0 0 0]
  lassign [run $CMD(seal)] r c
  return [list $r [get $LANE(sm) $SM]]
}
# OPEN a sealed message; returns {result plaintext}
proc open_sm {sealed} {
  global LANE CMD
  put $LANE(sm) $sealed
  lassign [run $CMD(open)] r c
  return [list $r [get $LANE(smmsg) 128]]
}
# the expected header: counter, length (8 bytes each, little-endian), 16 zero bytes
proc header {ctr len} {
  set h {}
  for {set i 0} {$i < 8} {incr i} { lappend h [expr {($ctr >> (8 * $i)) & 0xFF}] }
  for {set i 0} {$i < 8} {incr i} { lappend h [expr {($len >> (8 * $i)) & 0xFF}] }
  return [concat $h [lrepeat 16 0]]
}
set zero32 [lrepeat 32 0]

# 1
wait_idle
check "ID = PQSE, version 4.0, lifecycle TEST, power-on wipe done" \
  [expr {[rreg $REG(id)] == 0x50515345 && [rreg $REG(version)] == 0x00040000 && [rreg $REG(lifecycle)] == 0}]

# 2 known answers
put $LANE(injd) [load_hex kg_d]; put $LANE(injz) [load_hex kg_z]
lassign [run $CMD(keygen) 1] r c
check "masked KeyGen: ek matches NIST" [expr {$r == 0 && [get $LANE(ekown) $EK] eq [load_hex kg_ek]}] $c
put $LANE(xin) [load_hex en_ek]; put $LANE(injm) [load_hex en_m]
lassign [run $CMD(encaps) 1] r c
check "masked Encaps: c, K match NIST" [expr {$r == 0 && [get $LANE(xout) $CT] eq [load_hex en_c] && [get $LANE(k) 32] eq [load_hex en_k]}] $c
lassign [import_dk [load_hex de0_dk]] r c
put $LANE(xin) [load_hex de0_c]
lassign [run $CMD(decaps)] r c
check "masked Decaps (valid c): K matches NIST" [expr {$r == 0 && [get $LANE(k) 32] eq [load_hex de0_k]}] $c
lassign [import_dk [load_hex de1_dk]] r c
put $LANE(xin) [load_hex de1_c]
lassign [run $CMD(decaps)] r c
check "masked Decaps (modified c): implicit rejection K matches NIST" [expr {$r == 0 && [get $LANE(k) 32] eq [load_hex de1_k]}] $c

# 3 secure-element flow with TRNG seeds and the PUF
lassign [run $CMD(enroll)] r c
set helper [get $LANE(help) $HELP]
check "PUF enroll (RM(1,5) helper data 120 bytes + 8-byte key check value)" \
  [expr {$r == 0 && [lrange $helper 120 127] ne [lrepeat 8 0]}] $c
lassign [run $CMD(kgwrap)] r c
set ek   [get $LANE(ekown) $EK]
set blob [get $LANE(blob) $BLOB]
check "KeyGen (TRNG) + wrap" [expr {$r == 0}] $c
put $LANE(xin) $ek
lassign [run $CMD(encaps)] r c
set ct [get $LANE(xout) $CT]; set k1 [get $LANE(k) 32]
check "Encaps to the card's ek (TRNG m): initiator" [expr {$r == 0}] $c
set msg [test_msg 9]
lassign [seal $msg 0] r0 s0
lassign [seal $msg 129] r1 s1
check "SEAL refuses a length of 0 or 129 (result 1)" [expr {$r0 == 1 && $r1 == 1}]
set msg [test_msg 1]
lassign [seal $msg 128] r sealed
check "SEAL a 128-byte message with the session key (counter 0)" \
  [expr {$r == 0 && [lrange $sealed 32 159] ne $msg && [lrange $sealed 0 31] eq [header 0 128]}]
set msg2 [test_msg 3]
lassign [seal $msg2 100] r sealed2
check "SEAL a 100-byte message (counter 1, ciphertext bytes 100..127 are 0)" \
  [expr {$r == 0 && [lrange $sealed2 0 31] eq [header 1 100] && [lrange $sealed2 132 159] eq [lrepeat 28 0]}]
set msg3 [test_msg 5]
lassign [seal $msg3 1] r sealed3
check "SEAL a 1-byte message (counter 2)" [expr {$r == 0 && [lrange $sealed3 0 31] eq [header 2 1]}]
put $LANE(xin) $ct
lassign [run $CMD(decaps)] r c
check "masked Decaps: same K, responder" [expr {$r == 0 && [get $LANE(k) 32] eq $k1}] $c
lassign [open_sm $sealed] r p
check "OPEN: message 0 recovered" [expr {$r == 0 && $p eq $msg}]
lassign [open_sm $sealed] r p
check "OPEN: the same message again is rejected (replay, result 11)" [expr {$r == 11}]
lassign [open_sm $sealed3] r p
check "OPEN: message 2 before message 1 (out of order) is accepted, 1 byte" \
  [expr {$r == 0 && $p eq [concat [lrange $msg3 0 0] [lrepeat 127 0]]}]
set bad [lreplace $sealed2 70 70 [expr {[lindex $sealed2 70] ^ 0x40}]]
lassign [open_sm $bad] r p
check "OPEN: modified message rejected (result 9)" [expr {$r == 9}]
set bad [lreplace $sealed2 8 8 50]
lassign [open_sm $bad] r p
check "OPEN: modified length rejected (result 9)" [expr {$r == 9}]
lassign [open_sm $sealed2] r p
check "OPEN: the late message 1 still opens (100 bytes, the rest 0)" \
  [expr {$r == 0 && $p eq [concat [lrange $msg2 0 99] [lrepeat 28 0]]}]
lassign [run $CMD(zeroize)] r c
check "zeroize: no key, no session key" [expr {$r == 0 && ([rreg $REG(status)] & 0x10004) == 0}] $c
put $LANE(blob) $blob; put $LANE(help) $helper
lassign [run $CMD(unwrap)] r c
check "unwrap: same ek regenerated from the PUF-wrapped seed" [expr {$r == 0 && [get $LANE(ekown) $EK] eq $ek}] $c
set badhelp [lreplace $helper 121 121 [expr {[lindex $helper 121] ^ 0x10}]]
put $LANE(help) $badhelp
lassign [run $CMD(unwrap)] r c
check "unwrap with a wrong key check value: three attempts, then result 12" [expr {$r == 12}] $c
put $LANE(help) $helper

# 4 raw dumps (TEST only)
set fh [open puf_raw.txt w]
for {set i 0} {$i < $pqse_puf_dumps} {incr i} {
  lassign [run $CMD(pufraw)] r c
  if {$r != 0} { break }
  puts $fh [hexline [get $LANE(xout) $RAWB]]
}
close $fh
check "PUFRAW: $pqse_puf_dumps dumps -> puf_raw.txt" [expr {$r == 0}] $c
set fh [open trng_raw.txt w]
for {set i 0} {$i < $pqse_trng_dumps} {incr i} {
  lassign [run $CMD(trngraw)] r c
  if {$r != 0} { break }
  puts $fh [hexline [get $LANE(xout) $CT]]
}
close $fh
check "TRNGRAW: $pqse_trng_dumps dumps -> trng_raw.txt" [expr {$r == 0}] $c

# 5 lifecycle USER
wreg $REG(lifecycle) 1; wreg $REG(lifecycle) 2
lassign [import_dk [load_hex de0_dk]] r c
check "USER: key import refused (result 2)" [expr {$r == 2}]
lassign [run $CMD(keygen)] r c
set ek [get $LANE(ekown) $EK]
put $LANE(xin) $ek
lassign [run $CMD(encaps)] r c
set ct [get $LANE(xout) $CT]
check "USER: Encaps, K not readable" [expr {$r == 0 && [get $LANE(k) 32] eq $zero32}] $c
set msg [test_msg 2]
lassign [seal $msg 128] r sealed
put $LANE(xin) $ct
lassign [run $CMD(decaps)] r1 c
lassign [open_sm $sealed] r2 p
check "USER: SEAL / Decaps / OPEN with the internal session key" \
  [expr {$r == 0 && $r1 == 0 && $r2 == 0 && $p eq $msg && [get $LANE(k) 32] eq $zero32}]

# 6 tamper
puts "\nPress KEY1 (tamper) on the board now ..."
set t0 [clock milliseconds]
while {([rreg $REG(status)] & 0x20) == 0} {
  if {[clock milliseconds] - $t0 > 30000} { puts "(no tamper seen, skipping)"; break }
  after 100
}
if {[rreg $REG(status)] & 0x20} {
  wait_idle
  lassign [run $CMD(decaps)] r c
  check "tamper: KILLED, key wiped, commands refused (result 7)" [expr {[rreg $REG(lifecycle)] == 3 && ([rreg $REG(status)] & 4) == 0 && $r == 7}]
  puts "(reset the board with KEY0 to use it again)"
}

puts "\n[expr {$errors == 0 ? "ALL TESTS PASSED" : "$errors TEST(S) FAILED"}]"
close_service master $jm
