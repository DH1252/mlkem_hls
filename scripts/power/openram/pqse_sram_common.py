# pqse_sram_common.py - OpenRAM settings shared by the PQSE SRAM shapes (sky130).
# Included by pqse_sram_a*_d*.py:
#   exec(open(os.path.join(os.path.dirname(__file__), 'pqse_sram_common.py')).read())
#
# Purpose: SPICE-characterized read / write / idle energy and leakage of the
# exact RAM shapes PQSE uses, in place of the assumed energy per access of
# scripts/power/pqse_energy.py (make se-sram-char, see the Makefile).
#
# Environment (all optional; make se-sram-char passes them):
#   PQSE_OR_OUT      output directory (default ./openram_out)
#   PQSE_OR_PORTS    1rw1r (default: write on the rw port 0, read on port 1;
#                    the port type of the published sky130 macros) or 1r1w
#   PQSE_OR_LAYOUT   1: generate the layout too (area; needed for PEX). Default
#                    0: netlist only - characterization of the schematic
#                    netlist (no wire capacitance: energies a little low)
#   PQSE_OR_PEX      1 (with LAYOUT=1): characterize the extracted netlist
#                    (Magic; slowest, most accurate)
#   PQSE_OR_DRC      1 (with LAYOUT=1): run DRC / LVS (Magic, Netgen)
#   PQSE_OR_SPICE    ngspice (default), xa, hspice, spectre
#   PQSE_OR_THREADS  ngspice threads per simulation (default 4)
#   PQSE_OR_TABLE    1: OpenRAM's full 3 x 3 load / slew table (9 timing and
#                    power simulations at the minimum period). Default 0: one
#                    point, the nominal load (one flip-flop input) and slew -
#                    the energy per access hardly depends on them, and this
#                    cuts the run time several-fold
#   PQSE_OR_ANALYTICAL 1: OpenRAM's analytical model instead of SPICE: no
#                    ngspice, seconds and little memory, but a rough number:
#                    one C V^2 f power at the technology's event frequency
#                    (sky130: 100 MHz) for read, write and idle alike
#                    (pqse_sram_char.py converts it with --allow-analytical)
#   PQSE_OR_NIX      1: let OpenRAM set up its tools with Nix (`nix develop`,
#                    OpenRAM's default; needs nix). Default 0: the tools on PATH
#                    (netlist-only characterization needs only ngspice; layout,
#                    DRC / LVS and PEX also need Magic and Netgen)
import os as _os

use_nix = _os.environ.get("PQSE_OR_NIX", "0") == "1"

tech_name = "sky130"

# characterize the nominal corner only (TT, 1.8 V, 25 C - the corner of the
# sky130_fd_sc_hd__tt_025C_1v80 library the logic power uses)
nominal_corner_only = True
process_corners = ["TT"]
supply_voltages = [1.8]
temperatures = [25]

# SPICE characterization by default (the published sky130_sram_macros were
# built with the analytical model: one power value for read, write and
# deselected alike); PQSE_OR_ANALYTICAL=1 for that model
analytical_delay = _os.environ.get("PQSE_OR_ANALYTICAL", "0") == "1"
spice_name = _os.environ.get("PQSE_OR_SPICE", "ngspice")
num_sim_threads = int(_os.environ.get("PQSE_OR_THREADS", "4"))
# one load / slew point (SPICE only; the analytical model ignores it). OpenRAM
# warns that the lib's delay / slew tables are then that point repeated:
# fine here, pqse_sram_char.py reads only the power and the minimum period
# (do not use these libs for timing)
if _os.environ.get("PQSE_OR_TABLE", "0") != "1" and not analytical_delay:
    # (load fF, input slew ns): sky130 tech.py dff_in_cap and rise_time
    use_specified_load_slew = [(6.89, 0.005)]

_layout = _os.environ.get("PQSE_OR_LAYOUT", "0") == "1"
netlist_only = not _layout
use_pex = _layout and _os.environ.get("PQSE_OR_PEX", "0") == "1"
check_lvsdrc = _layout and _os.environ.get("PQSE_OR_DRC", "0") == "1"
route_supplies = "ring"
uniquify = True

# ports: PQSE's RAMs have one write port and one read port (pqse_ram_1r1w)
_ports = _os.environ.get("PQSE_OR_PORTS", "1rw1r")
if _ports == "1r1w":
    num_rw_ports, num_r_ports, num_w_ports = 0, 1, 1
else:
    num_rw_ports, num_r_ports, num_w_ports = 1, 1, 0

# whole-word writes (no byte enables)
write_size = None

output_name = "pqse_sram_a{0}_d{1}".format(int(num_words - 1).bit_length(), word_size)
output_path = _os.path.join(_os.environ.get("PQSE_OR_OUT", "openram_out"), output_name)
