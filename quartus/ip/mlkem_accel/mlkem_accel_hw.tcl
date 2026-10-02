# -----------------------------------------------------------------------------
# mlkem_accel_hw.tcl - Platform Designer component: ML-KEM accelerator.
#
# Written by scripts/package_ip.py - edit that script, not this file.
#
# Interfaces
#   clock         clock input (the design was scheduled by Bambu for 50 MHz)
#   reset         active-high reset, synchronous
#   avalon_slave  Avalon-MM slave, 32-bit, 16 KB span, read latency 1,
#                 no wait states (register map in hw/rtl/mlkem_avalon.v)
#   irq           interrupt: DONE and IRQ_EN
#
# Quartus reads the *.mem files named in the Bambu Verilog relative to the
# Quartus PROJECT directory, so copy them there as well (see the guide).
# -----------------------------------------------------------------------------
package require -exact qsys 16.1

set_module_property NAME mlkem_accel
set_module_property VERSION 1.0
set_module_property DISPLAY_NAME "ML-KEM accelerator (Bambu HLS)"
set_module_property DESCRIPTION "FIPS 203 ML-KEM KeyGen/Encaps/Decaps core generated from C with Bambu HLS, Avalon-MM mailbox interface"
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
set_fileset_property QUARTUS_SYNTH TOP_LEVEL mlkem_avalon
set_fileset_property QUARTUS_SYNTH ENABLE_RELATIVE_INCLUDE_PATHS false
set_fileset_property QUARTUS_SYNTH ENABLE_FILE_OVERWRITE_MODE false
add_fileset_file mlkem_avalon.v VERILOG PATH mlkem_avalon.v TOP_LEVEL_FILE
add_fileset_file mlkem_tdp_ram.v VERILOG PATH mlkem_tdp_ram.v
add_fileset_file mlkem_accel.v VERILOG PATH mlkem_accel.v
add_fileset_file mlkem_accel.sv SYSTEM_VERILOG PATH mlkem_accel.sv
add_fileset_file 0_array_ref_35251.mem OTHER PATH 0_array_ref_35251.mem
add_fileset_file 0_array_ref_35252.mem OTHER PATH 0_array_ref_35252.mem
add_fileset_file 0_array_ref_35253.mem OTHER PATH 0_array_ref_35253.mem
add_fileset_file 0_array_ref_35254.mem OTHER PATH 0_array_ref_35254.mem
add_fileset_file 0_array_ref_35255.mem OTHER PATH 0_array_ref_35255.mem
add_fileset_file 0_array_ref_35256.mem OTHER PATH 0_array_ref_35256.mem
add_fileset_file 0_array_ref_35257.mem OTHER PATH 0_array_ref_35257.mem
add_fileset_file 0_array_ref_35258.mem OTHER PATH 0_array_ref_35258.mem
add_fileset_file 0_array_ref_35259.mem OTHER PATH 0_array_ref_35259.mem
add_fileset_file 0_array_ref_35260.mem OTHER PATH 0_array_ref_35260.mem
add_fileset_file 0_array_ref_35261.mem OTHER PATH 0_array_ref_35261.mem
add_fileset_file 0_array_ref_35262.mem OTHER PATH 0_array_ref_35262.mem
add_fileset_file 0_array_ref_35263.mem OTHER PATH 0_array_ref_35263.mem
add_fileset_file 0_array_ref_35264.mem OTHER PATH 0_array_ref_35264.mem
add_fileset_file 0_array_ref_35265.mem OTHER PATH 0_array_ref_35265.mem
add_fileset_file 0_array_ref_35266.mem OTHER PATH 0_array_ref_35266.mem
add_fileset_file 0_array_ref_35267.mem OTHER PATH 0_array_ref_35267.mem
add_fileset_file 0_array_ref_35268.mem OTHER PATH 0_array_ref_35268.mem
add_fileset_file 0_array_ref_36282.mem OTHER PATH 0_array_ref_36282.mem
add_fileset_file 0_array_ref_36283.mem OTHER PATH 0_array_ref_36283.mem
add_fileset_file 0_array_ref_36284.mem OTHER PATH 0_array_ref_36284.mem
add_fileset_file 0_array_ref_36285.mem OTHER PATH 0_array_ref_36285.mem
add_fileset_file 0_array_ref_36286.mem OTHER PATH 0_array_ref_36286.mem
add_fileset_file 0_array_ref_36287.mem OTHER PATH 0_array_ref_36287.mem
add_fileset_file 0_array_ref_36288.mem OTHER PATH 0_array_ref_36288.mem
add_fileset_file 0_array_ref_36289.mem OTHER PATH 0_array_ref_36289.mem
add_fileset_file 0_array_ref_36290.mem OTHER PATH 0_array_ref_36290.mem
add_fileset_file 0_array_ref_36291.mem OTHER PATH 0_array_ref_36291.mem
add_fileset_file 0_array_ref_36292.mem OTHER PATH 0_array_ref_36292.mem
add_fileset_file 0_array_ref_36293.mem OTHER PATH 0_array_ref_36293.mem
add_fileset_file 0_array_ref_36294.mem OTHER PATH 0_array_ref_36294.mem
add_fileset_file 0_array_ref_36295.mem OTHER PATH 0_array_ref_36295.mem
add_fileset_file 0_array_ref_36296.mem OTHER PATH 0_array_ref_36296.mem
add_fileset_file 0_array_ref_36297.mem OTHER PATH 0_array_ref_36297.mem
add_fileset_file 0_array_ref_36298.mem OTHER PATH 0_array_ref_36298.mem
add_fileset_file 0_array_ref_36299.mem OTHER PATH 0_array_ref_36299.mem
add_fileset_file 0_array_ref_36300.mem OTHER PATH 0_array_ref_36300.mem
add_fileset_file 0_array_ref_36301.mem OTHER PATH 0_array_ref_36301.mem
add_fileset_file 0_array_ref_36302.mem OTHER PATH 0_array_ref_36302.mem
add_fileset_file 0_array_ref_36303.mem OTHER PATH 0_array_ref_36303.mem
add_fileset_file 0_array_ref_36304.mem OTHER PATH 0_array_ref_36304.mem
add_fileset_file 0_array_ref_36305.mem OTHER PATH 0_array_ref_36305.mem
add_fileset_file 0_array_ref_36306.mem OTHER PATH 0_array_ref_36306.mem
add_fileset_file 0_array_ref_36307.mem OTHER PATH 0_array_ref_36307.mem
add_fileset_file 0_array_ref_36308.mem OTHER PATH 0_array_ref_36308.mem
add_fileset_file 0_array_ref_36309.mem OTHER PATH 0_array_ref_36309.mem
add_fileset_file 0_array_ref_36310.mem OTHER PATH 0_array_ref_36310.mem
add_fileset_file 0_array_ref_36311.mem OTHER PATH 0_array_ref_36311.mem
add_fileset_file 0_array_ref_36312.mem OTHER PATH 0_array_ref_36312.mem
add_fileset_file 0_array_ref_36313.mem OTHER PATH 0_array_ref_36313.mem
add_fileset_file 0_array_ref_36314.mem OTHER PATH 0_array_ref_36314.mem
add_fileset_file 0_array_ref_36315.mem OTHER PATH 0_array_ref_36315.mem
add_fileset_file 0_array_ref_36316.mem OTHER PATH 0_array_ref_36316.mem
add_fileset_file 0_array_ref_36317.mem OTHER PATH 0_array_ref_36317.mem
add_fileset_file 0_array_ref_36318.mem OTHER PATH 0_array_ref_36318.mem
add_fileset_file 0_array_ref_36319.mem OTHER PATH 0_array_ref_36319.mem
add_fileset_file 0_array_ref_36320.mem OTHER PATH 0_array_ref_36320.mem
add_fileset_file 0_array_ref_36321.mem OTHER PATH 0_array_ref_36321.mem
add_fileset_file 0_array_ref_36322.mem OTHER PATH 0_array_ref_36322.mem
add_fileset_file 0_array_ref_36323.mem OTHER PATH 0_array_ref_36323.mem
add_fileset_file 0_array_ref_36324.mem OTHER PATH 0_array_ref_36324.mem
add_fileset_file 0_array_ref_36325.mem OTHER PATH 0_array_ref_36325.mem
add_fileset_file 0_array_ref_36326.mem OTHER PATH 0_array_ref_36326.mem
add_fileset_file 0_array_ref_36327.mem OTHER PATH 0_array_ref_36327.mem
add_fileset_file 0_array_ref_36328.mem OTHER PATH 0_array_ref_36328.mem
add_fileset_file 0_array_ref_36329.mem OTHER PATH 0_array_ref_36329.mem
add_fileset_file 0_array_ref_36330.mem OTHER PATH 0_array_ref_36330.mem
add_fileset_file 0_array_ref_36331.mem OTHER PATH 0_array_ref_36331.mem
add_fileset_file 0_array_ref_36332.mem OTHER PATH 0_array_ref_36332.mem
add_fileset_file 0_array_ref_36551.mem OTHER PATH 0_array_ref_36551.mem
add_fileset_file 0_array_ref_36552.mem OTHER PATH 0_array_ref_36552.mem
add_fileset_file 0_array_ref_36553.mem OTHER PATH 0_array_ref_36553.mem
add_fileset_file 0_array_ref_36554.mem OTHER PATH 0_array_ref_36554.mem
add_fileset_file 0_array_ref_36555.mem OTHER PATH 0_array_ref_36555.mem
add_fileset_file 0_array_ref_36556.mem OTHER PATH 0_array_ref_36556.mem
add_fileset_file 0_array_ref_36616.mem OTHER PATH 0_array_ref_36616.mem
add_fileset_file 0_array_ref_36617.mem OTHER PATH 0_array_ref_36617.mem
add_fileset_file 0_array_ref_36618.mem OTHER PATH 0_array_ref_36618.mem
add_fileset_file 0_array_ref_36619.mem OTHER PATH 0_array_ref_36619.mem
add_fileset_file 0_array_ref_36620.mem OTHER PATH 0_array_ref_36620.mem
add_fileset_file 0_array_ref_36710.mem OTHER PATH 0_array_ref_36710.mem
add_fileset_file 0_array_ref_36767.mem OTHER PATH 0_array_ref_36767.mem
add_fileset_file 0_array_ref_36768.mem OTHER PATH 0_array_ref_36768.mem
add_fileset_file 0_array_ref_36769.mem OTHER PATH 0_array_ref_36769.mem
add_fileset_file 0_array_ref_36770.mem OTHER PATH 0_array_ref_36770.mem
add_fileset_file 0_array_ref_37826.mem OTHER PATH 0_array_ref_37826.mem
add_fileset_file 0_array_ref_37827.mem OTHER PATH 0_array_ref_37827.mem
add_fileset_file 0_array_ref_37828.mem OTHER PATH 0_array_ref_37828.mem
add_fileset_file 0_array_ref_37829.mem OTHER PATH 0_array_ref_37829.mem
add_fileset_file 0_array_ref_38145.mem OTHER PATH 0_array_ref_38145.mem
add_fileset_file 0_array_ref_38265.mem OTHER PATH 0_array_ref_38265.mem
add_fileset_file 0_array_ref_38283.mem OTHER PATH 0_array_ref_38283.mem
add_fileset_file 0_array_ref_38552.mem OTHER PATH 0_array_ref_38552.mem
add_fileset_file 0_array_ref_38587.mem OTHER PATH 0_array_ref_38587.mem
add_fileset_file 0_array_ref_40301.mem OTHER PATH 0_array_ref_40301.mem
add_fileset_file array_ref_35251.mem OTHER PATH array_ref_35251.mem
add_fileset_file array_ref_35252.mem OTHER PATH array_ref_35252.mem
add_fileset_file array_ref_35253.mem OTHER PATH array_ref_35253.mem
add_fileset_file array_ref_35254.mem OTHER PATH array_ref_35254.mem
add_fileset_file array_ref_35255.mem OTHER PATH array_ref_35255.mem
add_fileset_file array_ref_35256.mem OTHER PATH array_ref_35256.mem
add_fileset_file array_ref_35257.mem OTHER PATH array_ref_35257.mem
add_fileset_file array_ref_35258.mem OTHER PATH array_ref_35258.mem
add_fileset_file array_ref_35259.mem OTHER PATH array_ref_35259.mem
add_fileset_file array_ref_35260.mem OTHER PATH array_ref_35260.mem
add_fileset_file array_ref_35261.mem OTHER PATH array_ref_35261.mem
add_fileset_file array_ref_35262.mem OTHER PATH array_ref_35262.mem
add_fileset_file array_ref_35263.mem OTHER PATH array_ref_35263.mem
add_fileset_file array_ref_35264.mem OTHER PATH array_ref_35264.mem
add_fileset_file array_ref_35265.mem OTHER PATH array_ref_35265.mem
add_fileset_file array_ref_35266.mem OTHER PATH array_ref_35266.mem
add_fileset_file array_ref_35267.mem OTHER PATH array_ref_35267.mem
add_fileset_file array_ref_35268.mem OTHER PATH array_ref_35268.mem
add_fileset_file array_ref_35995.mem OTHER PATH array_ref_35995.mem
add_fileset_file array_ref_36282.mem OTHER PATH array_ref_36282.mem
add_fileset_file array_ref_36283.mem OTHER PATH array_ref_36283.mem
add_fileset_file array_ref_36284.mem OTHER PATH array_ref_36284.mem
add_fileset_file array_ref_36285.mem OTHER PATH array_ref_36285.mem
add_fileset_file array_ref_36286.mem OTHER PATH array_ref_36286.mem
add_fileset_file array_ref_36287.mem OTHER PATH array_ref_36287.mem
add_fileset_file array_ref_36288.mem OTHER PATH array_ref_36288.mem
add_fileset_file array_ref_36289.mem OTHER PATH array_ref_36289.mem
add_fileset_file array_ref_36290.mem OTHER PATH array_ref_36290.mem
add_fileset_file array_ref_36291.mem OTHER PATH array_ref_36291.mem
add_fileset_file array_ref_36292.mem OTHER PATH array_ref_36292.mem
add_fileset_file array_ref_36293.mem OTHER PATH array_ref_36293.mem
add_fileset_file array_ref_36294.mem OTHER PATH array_ref_36294.mem
add_fileset_file array_ref_36295.mem OTHER PATH array_ref_36295.mem
add_fileset_file array_ref_36296.mem OTHER PATH array_ref_36296.mem
add_fileset_file array_ref_36297.mem OTHER PATH array_ref_36297.mem
add_fileset_file array_ref_36298.mem OTHER PATH array_ref_36298.mem
add_fileset_file array_ref_36299.mem OTHER PATH array_ref_36299.mem
add_fileset_file array_ref_36300.mem OTHER PATH array_ref_36300.mem
add_fileset_file array_ref_36301.mem OTHER PATH array_ref_36301.mem
add_fileset_file array_ref_36302.mem OTHER PATH array_ref_36302.mem
add_fileset_file array_ref_36303.mem OTHER PATH array_ref_36303.mem
add_fileset_file array_ref_36304.mem OTHER PATH array_ref_36304.mem
add_fileset_file array_ref_36305.mem OTHER PATH array_ref_36305.mem
add_fileset_file array_ref_36306.mem OTHER PATH array_ref_36306.mem
add_fileset_file array_ref_36307.mem OTHER PATH array_ref_36307.mem
add_fileset_file array_ref_36308.mem OTHER PATH array_ref_36308.mem
add_fileset_file array_ref_36309.mem OTHER PATH array_ref_36309.mem
add_fileset_file array_ref_36310.mem OTHER PATH array_ref_36310.mem
add_fileset_file array_ref_36311.mem OTHER PATH array_ref_36311.mem
add_fileset_file array_ref_36312.mem OTHER PATH array_ref_36312.mem
add_fileset_file array_ref_36313.mem OTHER PATH array_ref_36313.mem
add_fileset_file array_ref_36314.mem OTHER PATH array_ref_36314.mem
add_fileset_file array_ref_36315.mem OTHER PATH array_ref_36315.mem
add_fileset_file array_ref_36316.mem OTHER PATH array_ref_36316.mem
add_fileset_file array_ref_36317.mem OTHER PATH array_ref_36317.mem
add_fileset_file array_ref_36318.mem OTHER PATH array_ref_36318.mem
add_fileset_file array_ref_36319.mem OTHER PATH array_ref_36319.mem
add_fileset_file array_ref_36320.mem OTHER PATH array_ref_36320.mem
add_fileset_file array_ref_36321.mem OTHER PATH array_ref_36321.mem
add_fileset_file array_ref_36322.mem OTHER PATH array_ref_36322.mem
add_fileset_file array_ref_36323.mem OTHER PATH array_ref_36323.mem
add_fileset_file array_ref_36324.mem OTHER PATH array_ref_36324.mem
add_fileset_file array_ref_36325.mem OTHER PATH array_ref_36325.mem
add_fileset_file array_ref_36326.mem OTHER PATH array_ref_36326.mem
add_fileset_file array_ref_36327.mem OTHER PATH array_ref_36327.mem
add_fileset_file array_ref_36328.mem OTHER PATH array_ref_36328.mem
add_fileset_file array_ref_36329.mem OTHER PATH array_ref_36329.mem
add_fileset_file array_ref_36330.mem OTHER PATH array_ref_36330.mem
add_fileset_file array_ref_36331.mem OTHER PATH array_ref_36331.mem
add_fileset_file array_ref_36332.mem OTHER PATH array_ref_36332.mem
add_fileset_file array_ref_36551.mem OTHER PATH array_ref_36551.mem
add_fileset_file array_ref_36552.mem OTHER PATH array_ref_36552.mem
add_fileset_file array_ref_36553.mem OTHER PATH array_ref_36553.mem
add_fileset_file array_ref_36554.mem OTHER PATH array_ref_36554.mem
add_fileset_file array_ref_36555.mem OTHER PATH array_ref_36555.mem
add_fileset_file array_ref_36556.mem OTHER PATH array_ref_36556.mem
add_fileset_file array_ref_36616.mem OTHER PATH array_ref_36616.mem
add_fileset_file array_ref_36617.mem OTHER PATH array_ref_36617.mem
add_fileset_file array_ref_36618.mem OTHER PATH array_ref_36618.mem
add_fileset_file array_ref_36619.mem OTHER PATH array_ref_36619.mem
add_fileset_file array_ref_36620.mem OTHER PATH array_ref_36620.mem
add_fileset_file array_ref_36710.mem OTHER PATH array_ref_36710.mem
add_fileset_file array_ref_36767.mem OTHER PATH array_ref_36767.mem
add_fileset_file array_ref_36768.mem OTHER PATH array_ref_36768.mem
add_fileset_file array_ref_36769.mem OTHER PATH array_ref_36769.mem
add_fileset_file array_ref_36770.mem OTHER PATH array_ref_36770.mem
add_fileset_file array_ref_36896.mem OTHER PATH array_ref_36896.mem
add_fileset_file array_ref_37744.mem OTHER PATH array_ref_37744.mem
add_fileset_file array_ref_37826.mem OTHER PATH array_ref_37826.mem
add_fileset_file array_ref_37827.mem OTHER PATH array_ref_37827.mem
add_fileset_file array_ref_37828.mem OTHER PATH array_ref_37828.mem
add_fileset_file array_ref_37829.mem OTHER PATH array_ref_37829.mem
add_fileset_file array_ref_38145.mem OTHER PATH array_ref_38145.mem
add_fileset_file array_ref_38265.mem OTHER PATH array_ref_38265.mem
add_fileset_file array_ref_38283.mem OTHER PATH array_ref_38283.mem
add_fileset_file array_ref_38552.mem OTHER PATH array_ref_38552.mem
add_fileset_file array_ref_38587.mem OTHER PATH array_ref_38587.mem
add_fileset_file array_ref_40301.mem OTHER PATH array_ref_40301.mem

# ---- parameters -------------------------------------------------------------
add_parameter MLKEM_K INTEGER 3
set_parameter_property MLKEM_K DEFAULT_VALUE 3
set_parameter_property MLKEM_K DISPLAY_NAME "k of the generated core (read-only, shown in the PARAMS register)"
set_parameter_property MLKEM_K TYPE INTEGER
set_parameter_property MLKEM_K UNITS None
set_parameter_property MLKEM_K ALLOWED_RANGES {2 3 4}
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
