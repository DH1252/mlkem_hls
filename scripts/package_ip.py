#!/usr/bin/env python3
"""
package_ip.py - build the Platform Designer (Qsys) component folder.

Collects everything Quartus needs for the accelerator into one self-contained
folder, quartus/ip/mlkem_accel/, so that the folder can be copied as-is into
any Quartus project (the stand-alone JTAG design in quartus/jtag, or Terasic's
DE10-Nano GHRD):

    mlkem_accel_hw.tcl    component description (written by this script)
    mlkem_avalon.v        Avalon-MM wrapper          (from hw/rtl)
    mlkem_tdp_ram.v       mailbox RAM                (from hw/rtl)
    mlkem_accel.v         Bambu output               (from hw/bambu)
    mlkem_accel.sv        Bambu memory library       (from hw/bambu)
    *.mem                 Bambu memory contents      (from hw/bambu)

Run it again after every Bambu run (the Makefile target "ip" does).

Usage:  python3 scripts/package_ip.py [k]      k = 2, 3 (default) or 4
"""
import glob
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEST = os.path.join(ROOT, "quartus", "ip", "mlkem_accel")

HW_TCL = r"""# -----------------------------------------------------------------------------
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
@MEM_FILES@
# ---- parameters -------------------------------------------------------------
add_parameter MLKEM_K INTEGER @K@
set_parameter_property MLKEM_K DEFAULT_VALUE @K@
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
"""


def main():
    k = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    if k not in (2, 3, 4):
        sys.exit("k must be 2, 3 or 4")

    bambu = os.path.join(ROOT, "hw", "bambu")
    rtl = os.path.join(ROOT, "hw", "rtl")
    mems = sorted(glob.glob(os.path.join(bambu, "*.mem")))
    if not os.path.exists(os.path.join(bambu, "mlkem_accel.v")) or not mems:
        sys.exit("hw/bambu is empty - run the Bambu step first (make hls)")

    # Start from an empty folder so stale .mem files from an older run go away
    if os.path.isdir(DEST):
        for f in glob.glob(os.path.join(DEST, "*")):
            os.remove(f)
    else:
        os.makedirs(DEST)

    for f in ("mlkem_avalon.v", "mlkem_tdp_ram.v"):
        shutil.copy2(os.path.join(rtl, f), DEST)
    for f in ("mlkem_accel.v", "mlkem_accel.sv"):
        shutil.copy2(os.path.join(bambu, f), DEST)
    for f in mems:
        shutil.copy2(f, DEST)

    mem_lines = "".join(
        "add_fileset_file %s OTHER PATH %s\n" % (os.path.basename(f), os.path.basename(f))
        for f in mems
    )
    text = HW_TCL.replace("@MEM_FILES@", mem_lines).replace("@K@", str(k))
    with open(os.path.join(DEST, "mlkem_accel_hw.tcl"), "w", newline="\n") as fh:
        fh.write(text)

    print("packaged %d Verilog files and %d .mem files into %s (k = %d)"
          % (4, len(mems), os.path.relpath(DEST, ROOT), k))


if __name__ == "__main__":
    main()
