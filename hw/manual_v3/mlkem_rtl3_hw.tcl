# -----------------------------------------------------------------------------
# mlkem_rtl3_hw.tcl - Platform Designer component: the v3 hand-written
# ML-KEM-768 accelerator (hw/manual_v3). Same interfaces, register map and
# mailbox layout as mlkem_accel (Bambu), mlkem_rtl (v1) and mlkem_rtl2 (v2).
#   stand-alone design:  cd quartus/jtag && quartus_sh -t build.tcl rtl3
#   GHRD (ARM):          set CORE mlkem_rtl3 in quartus/ghrd/add_mlkem_to_ghrd.tcl
#
# UNTESTED FIRST VERSION: simulate it first (make sim-v3), see README.md.
# -----------------------------------------------------------------------------
package require -exact qsys 16.1

set_module_property NAME mlkem_rtl3
set_module_property VERSION 0.3
set_module_property DISPLAY_NAME "ML-KEM-768 accelerator v3 (hand-written RTL, parallel engines)"
set_module_property DESCRIPTION "FIPS 203 ML-KEM-768 KeyGen/Encaps/Decaps: hand-written Verilog with separate Keccak, NTT (8 butterflies, radix-4), pointwise and IO engines running in parallel under hardware hazard checking; clock-enable-based power reduction; Avalon-MM mailbox interface (same as mlkem_accel)"
set_module_property GROUP "Cryptography"
set_module_property AUTHOR "mlkem_hls tutorial"
set_module_property INTERNAL false
set_module_property OPAQUE_ADDRESS_MAP true
set_module_property INSTANTIATE_IN_SYSTEM_MODULE true
set_module_property EDITABLE false
set_module_property REPORT_TO_TALKBACK false
set_module_property ALLOW_GREYBOX_GENERATION false
set_module_property REPORT_HIERARCHY false

# ---- files ------------------------------------------------------------------
set FILES {mlkem_rtl3.v mlkem3_core.v mlkem3_ucode.v mlkem3_hash.v mlkem3_sample.v
           mlkem3_ntt.v mlkem3_pwm.v mlkem3_arith.v mlkem3_io.v mlkem3_mem.v}

add_fileset QUARTUS_SYNTH QUARTUS_SYNTH "" ""
set_fileset_property QUARTUS_SYNTH TOP_LEVEL mlkem_rtl3
set_fileset_property QUARTUS_SYNTH ENABLE_RELATIVE_INCLUDE_PATHS false
set_fileset_property QUARTUS_SYNTH ENABLE_FILE_OVERWRITE_MODE false
foreach f $FILES {
  if {$f eq "mlkem_rtl3.v"} {
    add_fileset_file $f VERILOG PATH $f TOP_LEVEL_FILE
  } else {
    add_fileset_file $f VERILOG PATH $f
  }
}

add_fileset SIM_VERILOG SIM_VERILOG "" ""
set_fileset_property SIM_VERILOG TOP_LEVEL mlkem_rtl3
set_fileset_property SIM_VERILOG ENABLE_RELATIVE_INCLUDE_PATHS false
set_fileset_property SIM_VERILOG ENABLE_FILE_OVERWRITE_MODE false
foreach f $FILES { add_fileset_file $f VERILOG PATH $f }

# ---- parameters -------------------------------------------------------------
add_parameter MLKEM_K INTEGER 3
set_parameter_property MLKEM_K DEFAULT_VALUE 3
set_parameter_property MLKEM_K DISPLAY_NAME "k (this core is ML-KEM-768 only)"
set_parameter_property MLKEM_K TYPE INTEGER
set_parameter_property MLKEM_K UNITS None
set_parameter_property MLKEM_K ALLOWED_RANGES {3}
set_parameter_property MLKEM_K ENABLED false
set_parameter_property MLKEM_K HDL_PARAMETER true

add_parameter KECCAK_RPC INTEGER 2
set_parameter_property KECCAK_RPC DEFAULT_VALUE 2
set_parameter_property KECCAK_RPC DISPLAY_NAME "Keccak rounds per clock (2: fast, 1: lower peak power)"
set_parameter_property KECCAK_RPC TYPE INTEGER
set_parameter_property KECCAK_RPC UNITS None
set_parameter_property KECCAK_RPC ALLOWED_RANGES {1 2}
set_parameter_property KECCAK_RPC HDL_PARAMETER true

add_parameter POLY_RAMSTYLE INTEGER 0
set_parameter_property POLY_RAMSTYLE DEFAULT_VALUE 0
set_parameter_property POLY_RAMSTYLE DISPLAY_NAME "Polynomial RAMs (0: M10K / auto, 1: MLAB)"
set_parameter_property POLY_RAMSTYLE TYPE INTEGER
set_parameter_property POLY_RAMSTYLE UNITS None
set_parameter_property POLY_RAMSTYLE ALLOWED_RANGES {0 1}
set_parameter_property POLY_RAMSTYLE HDL_PARAMETER true

# ---- clock ------------------------------------------------------------------
add_interface clock clock end
set_interface_property clock clockRate 0
set_interface_property clock ENABLED true
add_interface_port clock clk clk Input 1

# ---- reset ------------------------------------------------------------------
add_interface reset reset end
set_interface_property reset associatedClock clock
set_interface_property reset synchronousEdges BOTH
set_interface_property reset ENABLED true
add_interface_port reset reset reset Input 1

# ---- Avalon-MM slave --------------------------------------------------------
add_interface avalon_slave avalon end
set_interface_property avalon_slave addressUnits WORDS
set_interface_property avalon_slave associatedClock clock
set_interface_property avalon_slave associatedReset reset
set_interface_property avalon_slave bitsPerSymbol 8
set_interface_property avalon_slave burstOnBurstBoundariesOnly false
set_interface_property avalon_slave burstcountUnits WORDS
set_interface_property avalon_slave explicitAddressSpan 0
set_interface_property avalon_slave holdTime 0
set_interface_property avalon_slave linewrapBursts false
set_interface_property avalon_slave maximumPendingReadTransactions 0
set_interface_property avalon_slave maximumPendingWriteTransactions 0
set_interface_property avalon_slave readLatency 1
set_interface_property avalon_slave readWaitTime 0
set_interface_property avalon_slave setupTime 0
set_interface_property avalon_slave timingUnits Cycles
set_interface_property avalon_slave writeWaitTime 0
set_interface_property avalon_slave ENABLED true
add_interface_port avalon_slave avs_address address Input 12
add_interface_port avalon_slave avs_read read Input 1
add_interface_port avalon_slave avs_write write Input 1
add_interface_port avalon_slave avs_writedata writedata Input 32
add_interface_port avalon_slave avs_byteenable byteenable Input 4
add_interface_port avalon_slave avs_readdata readdata Output 32
set_interface_assignment avalon_slave embeddedsw.configuration.isFlash 0
set_interface_assignment avalon_slave embeddedsw.configuration.isMemoryDevice 0
set_interface_assignment avalon_slave embeddedsw.configuration.isNonVolatileStorage 0
set_interface_assignment avalon_slave embeddedsw.configuration.isPrintableDevice 0

# ---- interrupt --------------------------------------------------------------
add_interface irq interrupt end
set_interface_property irq associatedAddressablePoint avalon_slave
set_interface_property irq associatedClock clock
set_interface_property irq associatedReset reset
set_interface_property irq bridgedReceiverOffset ""
set_interface_property irq bridgesToReceiver ""
set_interface_property irq ENABLED true
add_interface_port irq irq irq Output 1
