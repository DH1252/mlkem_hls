# -----------------------------------------------------------------------------
# pqse_avalon_hw.tcl - Platform Designer component: the PQSE post-quantum
# secure element (hw/se) as an Avalon-MM slave (FPGA demo).
#   stand-alone design:  cd quartus/jtag && quartus_sh -t build.tcl se
#   register map:        hw/se/pqse_host.v, hw/se/README.md
#
# UNTESTED FIRST VERSION: simulate it first (make sim-se), see README.md.
# -----------------------------------------------------------------------------
package require -exact qsys 16.1

set_module_property NAME pqse_avalon
set_module_property VERSION 4.0
set_module_property DISPLAY_NAME "PQSE post-quantum secure element (ML-KEM-768, masked Decaps, PUF)"
set_module_property DESCRIPTION "Compact, low-power ML-KEM-768 secure element: one narrow datapath under microcode, first-order masked Decaps, shuffling and dummy cycles, TRNG with health tests, SRAM-cell PUF key wrapping, lifecycle states and tamper zeroization"
set_module_property GROUP "Cryptography"
set_module_property AUTHOR "mlkem_hls"
set_module_property INTERNAL false
set_module_property OPAQUE_ADDRESS_MAP true
set_module_property INSTANTIATE_IN_SYSTEM_MODULE true
set_module_property EDITABLE false
set_module_property REPORT_TO_TALKBACK false
set_module_property ALLOW_GREYBOX_GENERATION false
set_module_property REPORT_HIERARCHY false

# ---- files ------------------------------------------------------------------
set FILES {pqse_top.v pqse_host.v pqse_core.v pqse_ucode.v pqse_sponge.v pqse_keccak.v
           pqse_sample.v pqse_poly.v pqse_io.v pqse_masked.v pqse_mcomp.v pqse_puf.v
           pqse_rng.v pqse_arith.v pqse_mem.v pqse_spi.v pqse_perm.v}
set INCS  {pqse_defs.vh pqse_func.vh}

foreach fs {QUARTUS_SYNTH SIM_VERILOG} {
  add_fileset $fs $fs "" ""
  set_fileset_property $fs TOP_LEVEL pqse_avalon
  set_fileset_property $fs ENABLE_RELATIVE_INCLUDE_PATHS false
  set_fileset_property $fs ENABLE_FILE_OVERWRITE_MODE false
  foreach f $FILES {
    if {$f eq "pqse_top.v" && $fs eq "QUARTUS_SYNTH"} {
      add_fileset_file $f VERILOG PATH $f TOP_LEVEL_FILE
    } else {
      add_fileset_file $f VERILOG PATH $f
    }
  }
  foreach f $INCS { add_fileset_file $f VERILOG_INCLUDE PATH $f }
}

# ---- parameters -------------------------------------------------------------
add_parameter MASKED INTEGER 1
set_parameter_property MASKED DISPLAY_NAME "Masked Decaps (1) / unprotected reference build (0)"
set_parameter_property MASKED ALLOWED_RANGES {0 1}
set_parameter_property MASKED HDL_PARAMETER true

add_parameter RAMSTYLE INTEGER 0
set_parameter_property RAMSTYLE DISPLAY_NAME "Polynomial RAM (0: M10K / auto, 1: MLAB)"
set_parameter_property RAMSTYLE ALLOWED_RANGES {0 1}
set_parameter_property RAMSTYLE HDL_PARAMETER true

add_parameter PUF_WIN INTEGER 2048
set_parameter_property PUF_WIN DISPLAY_NAME "PUF counting window (clocks)"
set_parameter_property PUF_WIN HDL_PARAMETER true

add_parameter LC_RESET INTEGER 0
set_parameter_property LC_RESET DISPLAY_NAME "Lifecycle after reset (0 TEST, 1 PERSO, 2 USER)"
set_parameter_property LC_RESET ALLOWED_RANGES {0 1 2}
set_parameter_property LC_RESET HDL_PARAMETER true

# ---- clock / reset ----------------------------------------------------------
add_interface clock clock end
set_interface_property clock clockRate 0
add_interface_port clock clk clk Input 1

add_interface reset reset end
set_interface_property reset associatedClock clock
set_interface_property reset synchronousEdges BOTH
add_interface_port reset reset reset Input 1

# ---- Avalon-MM slave (word addresses, read latency 1) ------------------------
add_interface avalon_slave avalon end
set_interface_property avalon_slave addressUnits WORDS
set_interface_property avalon_slave associatedClock clock
set_interface_property avalon_slave associatedReset reset
set_interface_property avalon_slave bitsPerSymbol 8
set_interface_property avalon_slave readLatency 1
set_interface_property avalon_slave readWaitTime 0
set_interface_property avalon_slave writeWaitTime 0
set_interface_property avalon_slave timingUnits Cycles
set_interface_property avalon_slave maximumPendingReadTransactions 0
add_interface_port avalon_slave avs_address address Input 12
add_interface_port avalon_slave avs_read read Input 1
add_interface_port avalon_slave avs_write write Input 1
add_interface_port avalon_slave avs_writedata writedata Input 32
add_interface_port avalon_slave avs_readdata readdata Output 32

# ---- interrupt --------------------------------------------------------------
add_interface irq interrupt end
set_interface_property irq associatedAddressablePoint avalon_slave
set_interface_property irq associatedClock clock
set_interface_property irq associatedReset reset
add_interface_port irq irq irq Output 1

# ---- tamper input (exported: a push button on the board) ---------------------
add_interface tamper conduit end
add_interface_port tamper tamper export Input 1

# ---- measurement trigger (exported: a GPIO pin for the oscilloscope) ---------
# high during the masked comparison window, lifecycle TEST only
add_interface trig conduit end
add_interface_port trig trig export Output 1
