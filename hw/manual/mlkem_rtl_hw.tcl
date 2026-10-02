# -----------------------------------------------------------------------------
# mlkem_rtl_hw.tcl - Platform Designer component: the hand-written ML-KEM-768
# accelerator (hw/manual).
#
# Same interfaces, register map and mailbox layout as the Bambu component
# (quartus/ip/mlkem_accel, "mlkem_accel"), so either can be used in a system:
#   stand-alone design:  cd quartus/jtag && quartus_sh -t build.tcl rtl
#   GHRD (ARM):          set CORE mlkem_rtl in quartus/ghrd/add_mlkem_to_ghrd.tcl
#                        and put this folder on the IP search path
#
# Plain Verilog, no memory initialisation files.
#
# UNTESTED FIRST VERSION: simulate it first (make sim-manual), see README.md.
# -----------------------------------------------------------------------------
package require -exact qsys 16.1

set_module_property NAME mlkem_rtl
set_module_property VERSION 0.1
set_module_property DISPLAY_NAME "ML-KEM-768 accelerator (hand-written RTL)"
set_module_property DESCRIPTION "FIPS 203 ML-KEM-768 KeyGen/Encaps/Decaps in hand-written Verilog, Avalon-MM mailbox interface (same as mlkem_accel)"
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
add_fileset QUARTUS_SYNTH QUARTUS_SYNTH "" ""
set_fileset_property QUARTUS_SYNTH TOP_LEVEL mlkem_rtl
set_fileset_property QUARTUS_SYNTH ENABLE_RELATIVE_INCLUDE_PATHS false
set_fileset_property QUARTUS_SYNTH ENABLE_FILE_OVERWRITE_MODE false
add_fileset_file mlkem_rtl.v       VERILOG PATH mlkem_rtl.v TOP_LEVEL_FILE
add_fileset_file mlkem_rtl_core.v  VERILOG PATH mlkem_rtl_core.v
add_fileset_file mlkem_rtl_hash.v  VERILOG PATH mlkem_rtl_hash.v
add_fileset_file mlkem_rtl_arith.v VERILOG PATH mlkem_rtl_arith.v
add_fileset_file mlkem_rtl_io.v    VERILOG PATH mlkem_rtl_io.v
add_fileset_file mlkem_rtl_mem.v   VERILOG PATH mlkem_rtl_mem.v

add_fileset SIM_VERILOG SIM_VERILOG "" ""
set_fileset_property SIM_VERILOG TOP_LEVEL mlkem_rtl
set_fileset_property SIM_VERILOG ENABLE_RELATIVE_INCLUDE_PATHS false
set_fileset_property SIM_VERILOG ENABLE_FILE_OVERWRITE_MODE false
add_fileset_file mlkem_rtl.v       VERILOG PATH mlkem_rtl.v
add_fileset_file mlkem_rtl_core.v  VERILOG PATH mlkem_rtl_core.v
add_fileset_file mlkem_rtl_hash.v  VERILOG PATH mlkem_rtl_hash.v
add_fileset_file mlkem_rtl_arith.v VERILOG PATH mlkem_rtl_arith.v
add_fileset_file mlkem_rtl_io.v    VERILOG PATH mlkem_rtl_io.v
add_fileset_file mlkem_rtl_mem.v   VERILOG PATH mlkem_rtl_mem.v

# ---- parameters -------------------------------------------------------------
add_parameter MLKEM_K INTEGER 3
set_parameter_property MLKEM_K DEFAULT_VALUE 3
set_parameter_property MLKEM_K DISPLAY_NAME "k (this core is ML-KEM-768 only)"
set_parameter_property MLKEM_K TYPE INTEGER
set_parameter_property MLKEM_K UNITS None
set_parameter_property MLKEM_K ALLOWED_RANGES {3}
set_parameter_property MLKEM_K ENABLED false
set_parameter_property MLKEM_K HDL_PARAMETER true

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
