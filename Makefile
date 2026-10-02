# -----------------------------------------------------------------------------
# Makefile - the Linux / WSL part of the flow.
#
#   make check-env check the tools Bambu's co-simulation needs
#   make test      C model against all NIST ACVP vectors + unit tests, k = 2,3,4
#   make hls       Bambu: C -> Verilog, with co-simulation of the testbench
#   make hls-nosim Bambu without the co-simulation
#   make sim-rtl   Verilator: Avalon wrapper + Bambu core, ACVP vectors
#   make sim-manual  the same test on the hand-written core (hw/manual);
#                  TRACE=1 prints every microcode step
#   make sim-v2    the same test on the fast / low-power core (hw/manual_v2)
#   make sim-v3    the same test on the parallel-engine core (hw/manual_v3)
#   make sim-se    the post-quantum secure element (hw/se): NIST vectors,
#                  fully masked KeyGen / Encaps / Decaps, PUF wrap/unwrap with
#                  error correction, secure messaging, fault detection,
#                  lifecycle, tamper, SPI
#   make sim-se-tvla MASKED=1 N=200   leakage assessment (TVLA) of the
#                  masked Decaps; MASKED=0 is the positive control
#   make sim-se-fault [FOP=keygen] [FN=200]  fault-injection campaign (tamper
#                  testing): random bit flips, unchanged / detected / silent
#   make se-probe  exact first-order robust-probing check (glitches +
#                  transitions) of the masked gadgets (also run by sim-se)
#   make se-area   Yosys gate count of the secure element (MASKED=0/1)
#   make se-power SKY130_LIB=...  SKY130 power + timing (Yosys + OpenSTA)
#   make se-power-vcd SKY130_LIB=... RAM_MACRO=1  energy per command from a
#                  gate-level simulation (Verilator SAIF + OpenSTA)
#   make se-power-sample SKY130_LIB=... RAM_MACRO=1 GL_FMT=vcd GL_CLOCKS=<n>
#                  the same from sampled windows (fast with VCD)
#   make se-gowin [PUF=0|bfly] [MASKED=0] [FLAT=0]  fit on the Tang Nano 20K (GW2AR-18)
#   make se-gowin-eda [PUF=0|bfly] [MASKED=0]  the same with GowinSynthesis + Gowin P&R (gw_sh)
#   make se-gowin-bisect           GowinSynthesis errors per module (diagnosis)
#   make ip        package the Platform Designer component (quartus/ip)
#   make sw-emu    build + run the ARM program against a software model
#   make sw-arm    cross-compile the ARM program for the DE10-Nano
#   make vectors   regenerate test vectors (needs ACVP_JSON=...)
#   make clean
#
# The Quartus part runs wherever Quartus is installed (Windows is fine):
#   cd quartus/jtag && quartus_sh -t build.tcl        (Bambu core)
#   cd quartus/jtag && quartus_sh -t build.tcl rtl    (hand-written core)
#   cd quartus/jtag && quartus_sh -t build.tcl rtl2   (hand-written v2)
#   cd quartus/jtag && quartus_sh -t build.tcl rtl3   (hand-written v3)
#   cd quartus/jtag && quartus_sh -t build.tcl se     (secure element)
# -----------------------------------------------------------------------------
SHELL     := /bin/bash
.SHELLFLAGS := -o pipefail -c
CC        ?= gcc
CFLAGS    ?= -O2 -Wall -Wextra -Werror
BAMBU     ?= bambu
VERILATOR ?= verilator
CROSS     ?= arm-linux-gnueabihf-
PYTHON    ?= python3
BUILD     := build
SRC       := src/fips202.c src/poly.c src/mlkem.c
HDR       := $(wildcard src/*.h)
ACVP_JSON ?= ACVP-Server/gen-val/json-files

# Bambu settings (see the guide, "Bambu options")
BAMBU_FLAGS := --top-fname=mlkem_accel -I../../src -I../../hls \
               --generate-interface=INFER --compiler=I386_GCC8 \
               --device-name=5CSEMA5F31C6 --clock-period=20 --reset-level=high \
               -O2 --disable-function-proxy
BAMBU_SIM   := --generate-tb=../../hls/tb_accel.c --simulate --simulator=VERILATOR

# Bambu's co-simulation looks for Verilator's svdpi.h next to the verilator
# command (<dir of verilator>/../share/verilator/include/vltstd). That fails
# when verilator on the PATH is a symlink or wrapper outside its install tree
# (built from source, OSS CAD Suite, ...). Verilator knows where it really
# lives, so hand that folder to the compilers through CPATH as well.
VERILATOR_ROOT_DIR := $(shell $(VERILATOR) --getenv VERILATOR_ROOT 2>/dev/null)
HLS_ENV := CPATH="$(VERILATOR_ROOT_DIR)/include/vltstd$${CPATH:+:$$CPATH}"

.PHONY: all help check-env test hls hls-nosim sim-rtl sim-manual sim-v2 sim-v3 sim-se sim-se-tvla sim-se-fault se-area se-power se-power-vcd se-power-gl-build se-power-sample se-power-vcd-report se-gowin se-gowin-eda se-gowin-bisect se-probe ip sw-emu sw-arm vectors clean

all: test

help:
	@sed -n '3,35p' Makefile

$(BUILD):
	mkdir -p $@

# ---- C model --------------------------------------------------------------------
$(BUILD)/test_k%: test/test_acvp.c $(SRC) $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) -DMLKEM_K=$* -Isrc test/test_acvp.c $(SRC) -o $@

$(BUILD)/unit_k%: test/test_unit.c $(SRC) $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) -DMLKEM_K=$* -Isrc test/test_unit.c $(SRC) -o $@

test: $(BUILD)/test_k2 $(BUILD)/test_k3 $(BUILD)/test_k4 \
      $(BUILD)/unit_k2 $(BUILD)/unit_k3 $(BUILD)/unit_k4
	$(BUILD)/test_k2 vectors/ML-KEM-512.txt
	$(BUILD)/test_k3 vectors/ML-KEM-768.txt
	$(BUILD)/test_k4 vectors/ML-KEM-1024.txt
	$(BUILD)/unit_k2
	$(BUILD)/unit_k3
	$(BUILD)/unit_k4
	$(PYTHON) scripts/gen_keccak.py --check src/fips202.c

# ---- Bambu HLS ------------------------------------------------------------------
# Takes a few minutes; the co-simulation at the end runs hls/tb_accel.c against
# the generated Verilog. Results are copied to hw/bambu.
# hls/mlkem_hls.c includes all of src/*.c as one file, so that the inline /
# noinline attributes in src/hls.h shape the hardware (one instance per leaf).
# "make hls-nosim" skips the co-simulation (less memory and time).
check-env:
	@bash scripts/check_env.sh

hls: | $(BUILD)
	@BAMBU=$(BAMBU) bash scripts/check_env.sh
	rm -rf $(BUILD)/hls && mkdir -p $(BUILD)/hls
	@echo "running Bambu and the co-simulation (a few minutes), log: $(BUILD)/hls/bambu.log"
	@cd $(BUILD)/hls && $(HLS_ENV) $(BAMBU) ../../hls/mlkem_hls.c $(BAMBU_FLAGS) $(BAMBU_SIM) -v4 > bambu.log 2>&1 \
	  || bash ../../scripts/bambu_errors.sh bambu.log
	@log=$(BUILD)/hls/HLS_output/simulation/testbench.log; grep "PASS\|FAIL" $$log; \
	  if grep -q "Testbench returned: 0" $$log && ! grep -q "\[FAIL\]\|mismatch" $$log; \
	  then echo "co-simulation PASSED"; else echo "co-simulation FAILED - see $$log"; exit 1; fi
	mkdir -p hw/bambu && rm -f hw/bambu/*.mem
	cp $(BUILD)/hls/mlkem_accel.v $(BUILD)/hls/mlkem_accel.sv $(BUILD)/hls/*.mem hw/bambu/
	@echo "cycles per call (results.txt, in half-cycles):"; cat $(BUILD)/hls/results.txt
	@echo "now run: make sim-rtl ip"

hls-nosim: | $(BUILD)
	rm -rf $(BUILD)/hls && mkdir -p $(BUILD)/hls
	cd $(BUILD)/hls && $(BAMBU) ../../hls/mlkem_hls.c $(BAMBU_FLAGS) 2>&1 | tee bambu.log
	mkdir -p hw/bambu && rm -f hw/bambu/*.mem
	cp $(BUILD)/hls/mlkem_accel.v $(BUILD)/hls/mlkem_accel.sv $(BUILD)/hls/*.mem hw/bambu/
	@echo "NOT co-simulated - run 'make hls' before trusting this on the board"

# ---- RTL simulation of wrapper + core --------------------------------------------
sim-rtl: | $(BUILD)
	rm -rf $(BUILD)/rtlsim && mkdir -p $(BUILD)/rtlsim
	cp -r hw/sim/vectors $(BUILD)/rtlsim/ && cp hw/bambu/*.mem $(BUILD)/rtlsim/
	cd $(BUILD)/rtlsim && $(VERILATOR) --binary --timing -j 2 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_mlkem_avalon -Mdir obj -o ../vtb \
	    ../../hw/sim/tb_mlkem_avalon.sv ../../hw/rtl/mlkem_avalon.v ../../hw/rtl/mlkem_tdp_ram.v \
	    ../../hw/bambu/mlkem_accel.sv ../../hw/bambu/mlkem_accel.v > build.log 2>&1 \
	    || { tail -20 build.log; exit 1; }
	cd $(BUILD)/rtlsim && ./vtb | tee sim.log
	@grep -q "TEST PASSED" $(BUILD)/rtlsim/sim.log

# ---- the hand-written core (hw/manual), same testbench and vectors ------------------
# First version, not yet simulated: expect to debug it (hw/manual/README.md).
# TRACE=1 prints every instruction the sequencer issues.
sim-manual: | $(BUILD)
	rm -rf $(BUILD)/mansim && mkdir -p $(BUILD)/mansim
	cp -r hw/sim/vectors $(BUILD)/mansim/
	cd $(BUILD)/mansim && $(VERILATOR) --binary --timing -j 2 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_mlkem_avalon -Mdir obj -o ../vtb \
	    +define+MLKEM_DUT=mlkem_rtl $(if $(TRACE),+define+MLKEM_TRACE) \
	    ../../hw/sim/tb_mlkem_avalon.sv ../../hw/manual/*.v > build.log 2>&1 \
	    || { tail -20 build.log; exit 1; }
	cd $(BUILD)/mansim && ./vtb | tee sim.log
	@grep -q "TEST PASSED" $(BUILD)/mansim/sim.log

# ---- the v2 hand-written core (hw/manual_v2): faster, lower power -------------------
# Also a first version, not yet simulated (hw/manual_v2/README.md).
# TRACE=1 prints every issued instruction. (For the 1-round Keccak, change
# the KECCAK_RPC default in hw/manual_v2/mlkem_rtl2.v.)
sim-v2: | $(BUILD)
	rm -rf $(BUILD)/v2sim && mkdir -p $(BUILD)/v2sim
	cp -r hw/sim/vectors $(BUILD)/v2sim/
	cd $(BUILD)/v2sim && $(VERILATOR) --binary --timing -j 2 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_mlkem_avalon -Mdir obj -o ../vtb \
	    +define+MLKEM_DUT=mlkem_rtl2 $(if $(TRACE),+define+MLKEM_TRACE) \
	    ../../hw/sim/tb_mlkem_avalon.sv ../../hw/manual_v2/*.v > build.log 2>&1 \
	    || { tail -20 build.log; exit 1; }
	cd $(BUILD)/v2sim && ./vtb | tee sim.log
	@grep -q "TEST PASSED" $(BUILD)/v2sim/sim.log

# ---- the v3 hand-written core (hw/manual_v3): parallel engines -------------------------
# First version, not yet simulated (hw/manual_v3/README.md). MLKEM_SIM_CHECK
# turns on the NTT engine's read-after-write checker ("NTT CHECK FAIL").
# TRACE=1 prints every issued instruction and the engines' busy clocks.
sim-v3: | $(BUILD)
	rm -rf $(BUILD)/v3sim && mkdir -p $(BUILD)/v3sim
	cp -r hw/sim/vectors $(BUILD)/v3sim/
	cd $(BUILD)/v3sim && $(VERILATOR) --binary --timing -j 2 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_mlkem_avalon -Mdir obj -o ../vtb \
	    +define+MLKEM_DUT=mlkem_rtl3 +define+MLKEM_SIM_CHECK $(if $(TRACE),+define+MLKEM_TRACE) \
	    ../../hw/sim/tb_mlkem_avalon.sv ../../hw/manual_v3/*.v > build.log 2>&1 \
	    || { tail -20 build.log; exit 1; }
	cd $(BUILD)/v3sim && ./vtb | tee sim.log
	@if grep -q "CHECK FAIL" $(BUILD)/v3sim/sim.log; then echo "NTT pass-order check failed"; exit 1; fi
	@grep -q "TEST PASSED" $(BUILD)/v3sim/sim.log

# ---- the post-quantum secure element (hw/se) ---------------------------------------------
# TRACE=1 prints every microcode instruction. LOWPOWER=1 simulates the ASIC
# low-power variant (PQSE_LOWPOWER: operand isolation of the shared buses), as
# the sky130 power flows build it. Also runs the Python check of the
# masked-gadget and fuzzy-extractor math and the robust-probing check first,
# and after the simulation the independent KMAC check of the sealed messages
# and the PUF / TRNG statistics.
SE_SRC := $(wildcard hw/se/*.v)
sim-se: | $(BUILD)
	$(PYTHON) scripts/pqse_model.py
	$(PYTHON) scripts/pqse_probe_verify.py
	rm -rf $(BUILD)/sesim && mkdir -p $(BUILD)/sesim
	cp -r hw/sim/vectors $(BUILD)/sesim/
	cd $(BUILD)/sesim && $(VERILATOR) --binary --timing -j 2 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_pqse -Mdir obj -o ../vtb -I../../hw/se \
	    +define+PQSE_SIM_INIT $(if $(TRACE),+define+PQSE_TRACE) $(if $(filter 1,$(LOWPOWER)),+define+PQSE_LOWPOWER) \
	    ../../hw/sim/tb_pqse.sv $(addprefix ../../,$(SE_SRC)) > build.log 2>&1 \
	    || { tail -30 build.log; exit 1; }
	cd $(BUILD)/sesim && ./vtb | tee sim.log
	$(PYTHON) scripts/pqse_sm_check.py $(BUILD)/sesim/sm_vec.txt
	$(PYTHON) scripts/pqse_puf_stats.py --puf $(BUILD)/sesim/puf_raw.txt \
	    --trng $(BUILD)/sesim/trng_raw.txt --out $(BUILD)/sesim
	@grep -q "TEST PASSED" $(BUILD)/sesim/sim.log

# Leakage assessment (TVLA, fixed-vs-random m, first order) of the masked
# Decaps on a Hamming-distance power model: N traces (default 200).
# MASKED=1 is the protected design (expect "no first-order leakage"),
# MASKED=0 the positive control (expect leakage). SEED picks the message /
# coin set; TVLA's rule is two independent runs that must both cross 4.5 at
# the same clock:  make sim-se-tvla SEED=2, then
#   python3 scripts/pqse_tvla.py confirm build/tvla_m1_s1/tvla_t.txt build/tvla_m1_s2/tvla_t.txt
# Results in build/tvla_m<MASKED>_s<SEED>/: tvla_t.txt (t per clock), tvla_t.png.
# LOWPOWER=1: the operand-isolated ASIC variant (the one se-power* builds),
# results in build/tvla_m<MASKED>_s<SEED>_lp/.
MASKED ?= 1
N    ?= 200
SEED ?= 1
TVD  := $(BUILD)/tvla_m$(MASKED)_s$(SEED)$(if $(filter 1,$(LOWPOWER)),_lp)
sim-se-tvla: | $(BUILD)
	rm -rf $(TVD) && mkdir -p $(TVD)
	cp -r hw/sim/vectors $(TVD)/
	$(PYTHON) scripts/pqse_tvla.py gen $(N) $(TVD)/tvla_in.txt --seed $(SEED)
	cd $(TVD) && $(VERILATOR) --binary --timing -j 2 -O3 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_pqse_tvla -Mdir obj -o ../vtvla -I../../hw/se \
	    +define+PQSE_SIM_INIT +define+TVLA_MASKED=$(MASKED) $(if $(filter 1,$(LOWPOWER)),+define+PQSE_LOWPOWER) \
	    ../../hw/sim/tb_pqse_tvla.sv $(addprefix ../../,$(SE_SRC)) > build.log 2>&1 \
	    || { tail -30 build.log; exit 1; }
	cd $(TVD) && ./vtvla | tee sim.log
	$(PYTHON) scripts/pqse_tvla.py report $(TVD)/tvla_t.txt --traces $(N) \
	    --png $(TVD)/tvla_t.png

# Fault-injection campaign (tamper testing): FN runs (default 200), each from a
# power cycle, one random bit flipped (control, datapath, masked gadgets, every
# RAM, both shares) at a random clock of a NIST-vector masked Decaps (FOP=decaps)
# or KeyGen (FOP=keygen); scripts/pqse_fault_report.py sorts the outcomes into
# unchanged / detected / implicit rejection / SILENT (a wrong output with
# result 0: what fault attacks exploit) / hang, per target. The host watchdog
# is shortened to 2^21 clocks here (a hung run then ends with FAULT sooner).
#   make sim-se-fault [FOP=decaps|keygen] [FN=200] [SEED=1] [LOWPOWER=1] [FPAR=4]
# Every run is its own simulation process (a cold chip: nothing a fault left in
# a RAM or an unreset register carries into the next run), FPAR at a time.
# FMODE=chain runs them back to back in one process instead, with the chip
# state carried across the power cycles: that finds faults whose effect
# survives a reset and the power-on wipe (compare the two).
# Results in build/fault_<FOP>_s<SEED>/: fault_log.txt, fault_report.txt.
FOP   ?= decaps
FN    ?= 200
FMODE ?= fresh
FPAR  ?= 4
FTD := $(BUILD)/fault_$(FOP)_s$(SEED)$(if $(filter 1,$(LOWPOWER)),_lp)
sim-se-fault: | $(BUILD)
	rm -rf $(FTD) && mkdir -p $(FTD)
	cp -r hw/sim/vectors $(FTD)/
	cd $(FTD) && $(VERILATOR) --binary --timing -j 2 -O3 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_pqse_fault -Mdir obj -o ../vfault -I../../hw/se \
	    +define+PQSE_SIM_INIT +define+PQSE_FAULT_CAMPAIGN +define+PQSE_WD_LOG2=21 \
	    $(if $(filter 1,$(LOWPOWER)),+define+PQSE_LOWPOWER) \
	    ../../hw/sim/tb_pqse_fault.sv $(addprefix ../../,$(SE_SRC)) > build.log 2>&1 \
	    || { tail -30 build.log; exit 1; }
	if [ "$(FMODE)" = chain ]; then \
	    cd $(FTD) && ./vfault +n=$(FN) +seed=$(SEED) +op=$(FOP) | tee sim.log; \
	else \
	    cd $(FTD) && ./vfault +ref +n=$(FN) +seed=$(SEED) +op=$(FOP) | grep -v '^- ' | tee sim.log && \
	    test -s cref.txt && \
	    seq 0 $$(($(FN) - 1)) | xargs -P $(FPAR) -I{} ./vfault +one={} +cref=$$(cat cref.txt) \
	        +seed=$(SEED) +op=$(FOP) | grep -v '^- ' | tee -a sim.log && \
	    { cat fault_head.txt; for i in $$(seq 0 $$(($(FN) - 1))); do cat run_$$i.txt 2>/dev/null; done; } \
	        > fault_log.txt; \
	fi
	$(PYTHON) scripts/pqse_fault_report.py $(FTD)/fault_log.txt --vectors hw/sim/vectors \
	    | tee $(FTD)/fault_report.txt

# Gate-level area estimate with Yosys (generic cells; with SKY130_LIB=<path to
# sky130_fd_sc_hd__tt_025C_1v80.lib> it maps to the SkyWater 130 nm library).
# MASKED=0 gives the unprotected reference build for comparison.
MASKED ?= 1
se-area: | $(BUILD)
	mkdir -p $(BUILD)/searea
	yosys -q -l $(BUILD)/searea/yosys_m$(MASKED).log -p "read_verilog -Ihw/se $(SE_SRC); \
	    chparam -set MASKED $(MASKED) pqse_top; synth -top pqse_top -flatten; \
	    $(if $(SKY130_LIB),dfflibmap -liberty $(SKY130_LIB); abc -liberty $(SKY130_LIB);) stat \
	    $(if $(SKY130_LIB),-liberty $(SKY130_LIB))"
	@grep -A40 "Printing statistics" $(BUILD)/searea/yosys_m$(MASKED).log | tail -40

# Fit on the Tang Nano 20K (Gowin GW2AR-18): Yosys synth_gowin, then the LUT /
# flip-flop / BSRAM / multiplier counts against the device. PUF=1 (default)
# includes the SRAM-cell latch PUF array (960 cells, as in the FPGA build);
# PUF=bfly builds the same array from butterfly cells (two latches and an excite
# flip-flop per bit, no LUTs: ~1,920 LUTs move to ~2,880 flip-flops); PUF=0 synthesizes the
# simulation PUF model instead.
# Area options (the defaults aim at the fewest cells):
#   FLAT=1          flatten before synthesis, so constants, unused outputs and
#                   duplicate logic are optimized across module boundaries. The
#                   PUF cells keep their own hierarchy (keep_hierarchy), so the
#                   cross-coupled pairs are never restructured. FLAT=0: the old
#                   hierarchical run, which also lists the largest modules.
#   GOWIN_D=20000   LUT-mapping delay target in ps (the 50 MHz clock): abc9 then
#                   trades unneeded speed for area instead of mapping for the
#                   best possible delay. GOWIN_D= (empty): best delay.
#   GOWIN_MAXLUT=8  widest LUT abc9 may build: LUT5..LUT8 use the logic cells'
#                   MUX2_LUT5..8 muxes, which cost no LUT4. 4: LUT4 only (the
#                   same as synth_gowin -nowidelut); compare both.
#   DEVICE=20k      the board the counts are compared with: 20k (Tang Nano 20K)
#                   or 9k (Tang Nano 9K, GW1NR-9; use GOWIN_OPTS="-family gw1n")
#   GOWIN_OPTS      extra synth_gowin options. Newer Yosys: "-family gw2a"
#                   selects the GW2A family (the default is GW1N; the cell
#                   counts are nearly the same).
PUF ?= 1
FLAT ?= 1
DEVICE ?= 20k
GOWIN_D ?= 20000
GOWIN_MAXLUT ?= 8
GOWIN_OPTS ?=
GW := $(BUILD)/segowin/m$(MASKED)_p$(PUF)$(if $(filter 0,$(FLAT)),_hier)
GW_SYNTH = synth_gowin -top pqse_top $(if $(filter 0,$(FLAT)),-noflatten) $(GOWIN_OPTS)
se-gowin: | $(BUILD)
	mkdir -p $(BUILD)/segowin
	yosys -q -l $(GW).log -p "read_verilog -Ihw/se \
	    -DPQSE_LUTRAM_1R $(if $(filter 1,$(PUF)),-DPQSE_PUF_LATCH)$(if $(filter bfly,$(PUF)),-DPQSE_PUF_BFLY) $(SE_SRC); \
	    chparam -set MASKED $(MASKED) pqse_top; \
	    $(GW_SYNTH) -run :map_luts; \
	    sort; read_verilog -icells -lib -specify +/abc9_model.v; \
	    abc9 -maxlut $(GOWIN_MAXLUT) -W 500 $(if $(GOWIN_D),-D $(GOWIN_D)); clean; \
	    $(GW_SYNTH) -run map_cells:; \
	    tee -q -o $(GW)_modules.txt stat; setattr -mod -unset keep_hierarchy; flatten; stat" 2>&1 \
	    | { grep -v -E '^(Warning: found logic loop|    cell .*(u_c|g_cell)|      [AB]\[0\] --> Y)' || true; }
	@test $(PUF) = 1 && echo "(the PUF cells are cross-coupled gates by design: their 'logic loop' warnings are hidden)" || true
	$(PYTHON) scripts/pqse_fit.py $(GW).log --modules $(GW)_modules.txt --device $(DEVICE)

# The same fit with the vendor flow (Gowin EDA's gw_sh: GowinSynthesis with
# -opt_goal area, then place & route, so the report is the real fit). Options as
# for se-gowin; FREQ=<MHz> sets the clock constraint (default 27, the board's
# oscillator); MAP=2 tries GowinSynthesis's LUT5-oriented mapping, STEP=syn
# stops after synthesis. Reports: build/gowin/m<MASKED>_p<PUF>/pqse/impl/pnr/pqse.rpt.txt
GW_SH ?= gw_sh
se-gowin-eda:
	PUF=$(PUF) MASKED=$(MASKED) MAP=$(MAP) STEP=$(STEP) FREQ=$(FREQ) DEVICE=$(DEVICE) \
	    PLACE=$(PLACE) ROUTE=$(ROUTE) $(GW_SH) gowin/pqse_gowin.tcl

# Diagnosis: synthesize every secure-element module on its own with
# GowinSynthesis (STEP=syn) and count its errors, to find the module behind a
# GowinSynthesis error that names no source line. Leaves first: the first
# module with errors is the culprit (its parents inherit them). One log per
# module in build/gowin/bisect/<module>.log.
SE_MODULES := pqse_mulred pqse_modq24 pqse_ram_1r1w pqse_spi pqse_parse pqse_cbd \
              pqse_ro_src pqse_trng pqse_prng pqse_perm pqse_keccak pqse_sponge pqse_poly \
              pqse_io pqse_masked pqse_mcomp pqse_puf_raw pqse_puf pqse_ucode pqse_host \
              pqse_core pqse_sys pqse_top
se-gowin-bisect:
	@mkdir -p $(BUILD)/gowin/bisect
	@for m in $(SE_MODULES); do \
	  log=$(BUILD)/gowin/bisect/$$m.log; \
	  PUF=$(PUF) MASKED=$(MASKED) STEP=syn TOP=$$m $(GW_SH) gowin/pqse_gowin.tcl > $$log 2>&1; \
	  printf '%-16s %3s SP00018  %3s ERROR total\n' $$m \
	    "$$(grep -c 'SP00018' $$log)" "$$(grep -c 'ERROR' $$log)"; \
	done

# Power and timing estimate on SkyWater 130 nm: Yosys maps the design to
# sky130_fd_sc_hd, OpenSTA (sta) reports power (vectorless with ACT toggles
# per clock, or from a gate-level VCD=<file> SCOPE=<instance>) and the slowest
# path against the 50 MHz clock. See scripts/pqse_power.tcl for what the
# numbers mean. STA=openroad runs the same script in OpenROAD (which contains
# OpenSTA). The netlist must be plain structural Verilog for OpenSTA: newer
# Yosys keeps $scopeinfo cells (with #(...) parameters) after flattening, so
# they are deleted before writing, and OpenSTA's reader does not take "signed"
# declarations (Yosys writes them for leftover integer loop variables), so sed
# drops that keyword.
STA ?= sta
ACT ?= 0.1
# delay target for ABC (ps, the 50 MHz clock of pqse_power.tcl): with it ABC
# buffers high-fan-out nets and sizes the gates; without it a RAM's address
# decode (the RAMs become flip-flops here) drives thousands of inputs from one
# gate, with transition times of microseconds, which wrecks the timing report
# and inflates the internal power (it grows with the input slew)
PERIOD_PS ?= 20000
# RAM_MACRO=1: the RAMs become black-box SRAM macros (scripts/power/
# pqse_ram_macro.v replaces hw/se/pqse_mem.v; scripts/power/pqse_sram_lib.py
# writes their Liberty stub: pins, 2 ns clock to data, no power). The report
# then covers the logic only - built from flip-flops, the RAMs dominate the
# power (every bit clocked every cycle) and their decode trees the timing.
# se-power-vcd adds the macros' energy from their access counts.
# (v4: the 128 x 7 shuffle table is a register array, not pqse_ram_1r1w: it
# stays flip-flops.)
RAM_MACRO ?= 0
# CLOCKGATE=1 (default): Yosys clockgate turns every group of at least CG_MIN
# flip-flops with a common enable into plain flip-flops behind one integrated
# clock gate (sky130_fd_sc_hd__dlclkp_1, enable latched while the clock is
# low): a register that holds its value is then not clocked at all - the
# clock-pin power of an idle flip-flop is most of its power. CLOCKGATE=0 keeps
# enable flip-flops (a mux feedback, clocked every cycle), as before.
# LOWPOWER=0 builds without PQSE_LOWPOWER (operand isolation of the shared
# buses), which the power flows enable by default.
CLOCKGATE ?= 1
CG_MIN    ?= 4
# CG_SRST=1 (default): registers written as "if (rst) ... else if (en) ..."
# (synchronous reset over the enable, the style of most engines here) are
# rewritten by dfflegalize into enable-over-reset form with enable = en | rst
# (same behaviour), which clockgate can gate; it skips the reset-over-enable
# form, and the first gate-level run showed 1,865 of 3,750 flip-flops clocked
# every cycle, ~80 % of the logic energy. Every other flip-flop type is listed
# as allowed, so dfflegalize leaves it alone. dfflegalize works bit by bit (one
# en | rst gate per flip-flop); opt_merge then merges the identical gates and
# opt_clean replaces the merged gates' output wires by the kept one in every
# flip-flop (clockgate groups flip-flops by the enable wire itself, without
# resolving aliases, and gates groups of CG_MIN or more).
CG_SRST   ?= 1
PW_CGLEG  := $(if $(and $(filter 1,$(CLOCKGATE)),$(filter 1,$(CG_SRST))),dfflegalize \
	    -cell \$$_DFF_?_ 01 -cell \$$_DFFE_??_ 01 -cell \$$_DFF_???_ 01 -cell \$$_DFFE_????_ 01 \
	    -cell \$$_ALDFF_??_ 01 -cell \$$_ALDFFE_???_ 01 -cell \$$_DFFSR_???_ 01 -cell \$$_DFFSRE_????_ 01 \
	    -cell \$$_SDFF_???_ 01 -cell \$$_SDFFCE_????_ 01 -cell \$$_SR_??_ 01 \
	    -cell \$$_DLATCH_?_ 01 -cell \$$_DLATCH_???_ 01 -cell \$$_DLATCHSR_???_ 01; opt_merge; opt_clean;,)
PW_SRC    := $(if $(filter 1,$(RAM_MACRO)),$(filter-out hw/se/pqse_mem.v,$(SE_SRC)) scripts/power/pqse_ram_macro.v,$(SE_SRC))
PW_RAMLIB := $(if $(filter 1,$(RAM_MACRO)),$(BUILD)/sepower/pqse_sram.lib,)
PW_DEFS   := $(if $(filter 0,$(LOWPOWER)),,-DPQSE_LOWPOWER)
PW_CG     := $(if $(filter 1,$(CLOCKGATE)),clockgate -pos sky130_fd_sc_hd__dlclkp_1 GATE:CLK:GCLK -min_net_size $(CG_MIN);,)
PW_TAG    := _m$(MASKED)$(if $(PW_RAMLIB),_rammacro)$(if $(PW_CG),_cg)$(if $(PW_DEFS),_lp)
# ABC_BUF=1 (default): after mapping, ABC buffers high-fan-out nets and sizes
# the gates (buffer / upsize / dnsize, as OpenROAD-flow-scripts does). Without
# it a control signal can drive hundreds of inputs from a size-1 gate, with
# transition times of ~10 ns: the slowest path is then that net, and the
# internal power, which grows with the input slew, is overstated.
# The sky130 lpflow_* (power-domain isolation, keep-alive) and probe cells are
# not used for logic (the OpenROAD-flow-scripts sky130hd don't-use list): ABC
# otherwise picks e.g. lpflow_inputiso1p_1 as a cheap OR gate.
ABC_BUF   ?= 1
PW_ABCF   := $(BUILD)/sepower/abc_map.script
# (only combinational logic reaches ABC - dfflibmap mapped the flip-flops - so
# the sequential steps of Yosys' default script, scorr / dretime, are left out)
PW_ABCGEN  = printf '%s\n' strash '&get -n' '&fraig -x' '&put' dc2 strash '&get -n' \
	    '&dch -f' '&nf -D $(PERIOD_PS)' '&put' \
	    $(if $(filter 1,$(ABC_BUF)),'buffer -c' topo 'stime -c' 'upsize -c' 'dnsize -c') > $(PW_ABCF)
PW_DONTUSE = $(foreach c,$(sort $(shell grep -oE 'sky130_fd_sc_hd__(lpflow_|probe)[A-Za-z0-9_]*' $(SKY130_LIB) 2>/dev/null)),-dont_use $(c))
# the mapping, shared by se-power and se-power-vcd (clockgate before dfflibmap:
# it works on the generic enable flip-flops)
PW_MAP     = read_verilog $(PW_DEFS) -Ihw/se $(PW_SRC); \
	    chparam -set MASKED $(MASKED) pqse_top; synth -top pqse_top -flatten; \
	    delete t:\$$scopeinfo; $(PW_CGLEG) $(PW_CG) \
	    dfflibmap -liberty $(SKY130_LIB); \
	    abc -liberty $(SKY130_LIB) -D $(PERIOD_PS) -script $(PW_ABCF) $(PW_DONTUSE); opt_clean; \
	    setundef -zero; hilomap -singleton -hicell sky130_fd_sc_hd__conb_1 HI -locell sky130_fd_sc_hd__conb_1 LO;
se-power: | $(BUILD)
	@test -n "$(SKY130_LIB)" || { echo "set SKY130_LIB=<path to sky130_fd_sc_hd__tt_025C_1v80.lib>"; exit 1; }
	@command -v $(STA) >/dev/null 2>&1 || { echo "$(STA) not found: install OpenSTA (not part of OSS CAD Suite),"; \
	    echo "or use OpenROAD, which contains it: make se-power STA=openroad"; exit 1; }
	mkdir -p $(BUILD)/sepower
	$(PW_ABCGEN)
	$(if $(PW_RAMLIB),$(PYTHON) scripts/power/pqse_sram_lib.py $(PW_RAMLIB))
	yosys -q -l $(BUILD)/sepower/yosys$(PW_TAG).log -p "$(PW_MAP) \
	    write_verilog -noattr -noexpr $(BUILD)/sepower/pqse_top_sky130.v"
	@grep -h "Converted .* FFs" $(BUILD)/sepower/yosys$(PW_TAG).log | sed 's/^/clockgate: /' || true
	sed -i -E 's/^([[:space:]]*(wire|input|output|reg))[[:space:]]+signed[[:space:]]/\1 /' $(BUILD)/sepower/pqse_top_sky130.v
	$(PYTHON) scripts/power/pqse_ff_report.py $(BUILD)/sepower/pqse_top_sky130.v > $(BUILD)/sepower/ffs$(PW_TAG).txt
	@head -25 $(BUILD)/sepower/ffs$(PW_TAG).txt; echo "(all: $(BUILD)/sepower/ffs$(PW_TAG).txt)"
	SKY130_LIB=$(SKY130_LIB) RAM_LIB=$(PW_RAMLIB) NETLIST=$(BUILD)/sepower/pqse_top_sky130.v ACT=$(ACT) VCD=$(VCD) SCOPE=$(SCOPE) \
	    $(STA) -no_splash -exit scripts/pqse_power.tcl 2>&1 | tee $(BUILD)/sepower/power$(PW_TAG).txt

# Energy per command from a gate-level simulation: the sky130 netlist (names
# enumerated, so the dump and the netlist OpenSTA reads use the same plain
# names), behavioural cell models generated from the Liberty file
# (scripts/pqse_lib2v.py: zero delay, every flip-flop starts at 0; the clock
# gates as latch + AND), with RAM_MACRO=1 SRAM macro models that count their
# reads and writes, Verilator, and a pin-level testbench (hw/sim/tb_pqse_gate.sv)
# that starts command GL_CMD over SPI and records every cell pin's toggles:
#   GL_LEN=0 (default)  the whole command, start to done (irq)
#   GL_LEN=<n>          n clocks from GL_START clocks into it; pass
#                       GL_CLOCKS=<clocks of the command> (make sim-se prints
#                       them) to extrapolate the energy per command
# GL_FMT=saif (default) needs Verilator 5.036 or newer (--trace-saif): toggle
# counts per pin, megabytes for a whole command. GL_FMT=vcd works with older
# ones, but a VCD grows ~100 MB per 1000 clocks: use a window then.
# OpenSTA reads the dump (power over the window), scripts/power/pqse_energy.py
# turns it into energy (+ the SRAM macros' energy from the access counts:
# SRAM_EPB_RD / SRAM_EPB_WR pJ per bit, SRAM_E0 pJ per access - assumptions,
# replace them with the SRAM compiler's datasheet) and into power at the
# smart-card clock CARD_MHZ.
#   make se-power-vcd SKY130_LIB=... RAM_MACRO=1 [GL_CMD=1] [GL_FMT=saif]
# Results in build/sepower/gl/: power_gl<tag>.txt, energy<tag>.txt. The
# Verilator build of the netlist takes minutes and several GB of memory; a
# whole KeyGen (~0.23 M clocks in v4) runs for minutes.
GL_CMD    ?= 1
GL_START  ?= 0
GL_LEN    ?= 0
GL_FMT    ?= saif
GL_MAX    ?= 20000000
GL_CLOCKS ?=
GL_SCOPE  ?= auto
CARD_MHZ  ?= 3.39
SRAM_EPB_RD ?= 0.5
SRAM_EPB_WR ?= 0.8
SRAM_E0     ?= 2.0
GLD       := $(BUILD)/sepower/gl
GL_DUMP   := gate.$(if $(filter vcd,$(GL_FMT)),vcd,saif)
# --trace-underscore: Yosys names every internal net _<n>_, and Verilator leaves
# names starting with "_" out of the dump unless told otherwise
GL_TRACE  := $(if $(filter vcd,$(GL_FMT)),--trace,--trace-saif) --trace-underscore
# speed: GL_JOBS parallel C++ compiles of the (large) Verilator model (default:
# all cores); GL_THREADS > 1 runs the model multithreaded (worth it for the
# whole netlist: try 4); GL_TRACE_THREADS=1 writes the VCD from a separate
# thread (VCD only)
GL_JOBS          ?= $(shell nproc 2>/dev/null || echo 2)
GL_THREADS       ?= 1
GL_TRACE_THREADS ?= 0
GL_VFLAGS := -j $(GL_JOBS) --build-jobs $(GL_JOBS) $(if $(filter-out 0 1,$(GL_THREADS)),--threads $(GL_THREADS)) \
	    $(if $(and $(filter vcd,$(GL_FMT)),$(filter-out 0,$(GL_TRACE_THREADS))),--trace-threads $(GL_TRACE_THREADS))
# the netlist, its cell / SRAM models and the Verilator model (shared by
# se-power-vcd and se-power-sample)
se-power-gl-build: | $(BUILD)
	@test -n "$(SKY130_LIB)" || { echo "set SKY130_LIB=<path to sky130_fd_sc_hd__tt_025C_1v80.lib>"; exit 1; }
	@command -v $(STA) >/dev/null 2>&1 || { echo "$(STA) not found: install OpenSTA (not part of OSS CAD Suite),"; \
	    echo "or use OpenROAD, which contains it: STA=openroad"; exit 1; }
	mkdir -p $(GLD)
	$(PW_ABCGEN)
	$(if $(PW_RAMLIB),$(PYTHON) scripts/power/pqse_sram_lib.py $(PW_RAMLIB) --models $(GLD)/sram_models.sv)
	yosys -q -l $(GLD)/yosys$(PW_TAG).log -p "$(PW_MAP) \
	    rename -hide w:* i:* o:* %u %d; rename -hide c:*; rename -enumerate; \
	    write_verilog -noattr -noexpr $(GLD)/pqse_top_gl.v"
	@grep -h "Converted .* FFs" $(GLD)/yosys$(PW_TAG).log | sed 's/^/clockgate: /' || true
	sed -i -E 's/^([[:space:]]*(wire|input|output|reg))[[:space:]]+signed[[:space:]]/\1 /' $(GLD)/pqse_top_gl.v
	$(PYTHON) scripts/pqse_lib2v.py $(SKY130_LIB) $(GLD)/pqse_top_gl.v $(GLD)/sky130_cells.v
	cd $(GLD) && $(VERILATOR) --binary --timing $(GL_TRACE) $(GL_VFLAGS) -Wno-fatal -Wno-lint -Wno-style \
	    --x-assign 0 --x-initial 0 --timescale 1ns/1ps --top-module tb_pqse_gate -Mdir obj -o ../vtb_gl \
	    $(CURDIR)/hw/sim/tb_pqse_gate.sv sky130_cells.v $(if $(PW_RAMLIB),sram_models.sv) pqse_top_gl.v > build.log 2>&1 \
	    || { tail -30 build.log; exit 1; }

PW_EARGS = --card-mhz $(CARD_MHZ) --epb-rd $(SRAM_EPB_RD) --epb-wr $(SRAM_EPB_WR) --e0 $(SRAM_E0) \
	    $(if $(GL_CLOCKS),--command-clocks $(GL_CLOCKS))
se-power-vcd: se-power-gl-build
	rm -f $(GLD)/gate.vcd $(GLD)/gate.saif $(GLD)/gl_run.txt $(GLD)/sram_access.txt
	cd $(GLD) && ./vtb_gl +cmd=$(GL_CMD) +start=$(GL_START) +len=$(GL_LEN) +max=$(GL_MAX) +vcd=$(GL_DUMP)
	$(MAKE) --no-print-directory se-power-vcd-report

# OpenSTA + energy again on the dump of the last se-power-vcd run (no new
# simulation), e.g. with other SRAM energies or another SCOPE:
#   make se-power-vcd-report SKY130_LIB=... RAM_MACRO=1 [GL_FMT=...] [GL_SCOPE=...]
# The dump holds the netlist's nets; OpenSTA annotates cell pins only, so
# scripts/power/pqse_pin_saif.py first maps every net's toggles onto the pins it
# connects (gate_pins.saif), which OpenSTA reads.
se-power-vcd-report:
	@test -f $(GLD)/$(GL_DUMP) || { echo "no $(GLD)/$(GL_DUMP): run make se-power-vcd first (same GL_FMT)"; exit 1; }
	$(PYTHON) scripts/power/pqse_pin_saif.py $(GLD)/pqse_top_gl.v $(GLD)/$(GL_DUMP) $(GLD)/gate_pins.saif --scope $(GL_SCOPE)
	SKY130_LIB=$(SKY130_LIB) RAM_LIB=$(PW_RAMLIB) NETLIST=$(GLD)/pqse_top_gl.v VCD=$(GLD)/gate_pins.saif SCOPE=auto \
	    $(STA) -no_splash -exit scripts/pqse_power.tcl 2>&1 | tee $(GLD)/power_gl$(PW_TAG).txt
	$(PYTHON) scripts/power/pqse_energy.py $(GLD)/power_gl$(PW_TAG).txt --run $(GLD)/gl_run.txt \
	    --dump $(GLD)/gate_pins.saif $(if $(PW_RAMLIB),--sram $(GLD)/sram_access.txt) \
	    $(PW_EARGS) | tee $(GLD)/energy$(PW_TAG).txt

# Sampled energy per command, the fast way with VCD: GL_WINDOWS windows of
# GL_WLEN clocks, one in the middle of each 1/GL_WINDOWS of the command
# (GL_CLOCKS clocks long: make sim-se prints it), simulated GL_PAR at a time
# (each simulation runs untraced, fast, up to its window and stops at its
# end); one OpenSTA run per window (GL_STA_PAR at a time: each needs the
# whole netlist in memory), then pqse_energy.py: the mean energy per clock x
# GL_CLOCKS, with the spread between the windows as its uncertainty.
#   make se-power-sample SKY130_LIB=... RAM_MACRO=1 GL_FMT=vcd GL_CLOCKS=<n>
#        [GL_WINDOWS=8] [GL_WLEN=2000] [GL_PAR=4] [GL_STA_PAR=2]
# 8 x 2000 clocks is ~2 % of a v5 KeyGen: ~1-3 GB of VCD instead of ~100 GB.
# Results in build/sepower/gl/win/w<i>/ and build/sepower/gl/energy_sampled<tag>.txt.
GL_WINDOWS ?= 8
GL_WLEN    ?= 2000
GL_PAR     ?= 4
GL_STA_PAR ?= 2
se-power-sample: se-power-gl-build
	@test -n "$(GL_CLOCKS)" || { echo "set GL_CLOCKS=<clocks of the command> (make sim-se prints them)"; exit 1; }
	rm -rf $(GLD)/win && mkdir -p $(GLD)/win
	seq 0 $$(($(GL_WINDOWS) - 1)) | xargs -P $(GL_PAR) -I{} sh -c '\
	    i={}; s=$$(( $(GL_CLOCKS) * (2 * i + 1) / (2 * $(GL_WINDOWS)) - $(GL_WLEN) / 2 )); [ $$s -ge 0 ] || s=0; \
	    mkdir -p $(GLD)/win/w$$i && cd $(GLD)/win/w$$i && \
	    ../../vtb_gl +cmd=$(GL_CMD) +start=$$s +len=$(GL_WLEN) +max=$(GL_MAX) +vcd=$(GL_DUMP) > sim.log 2>&1 \
	    && echo "window $$i (clocks $$s..$$((s + $(GL_WLEN)))): simulated" || { echo "window $$i: simulation failed"; tail -5 sim.log; exit 1; }'
	ls -d $(GLD)/win/w* | xargs -P $(GL_STA_PAR) -I{} sh -c '\
	    $(PYTHON) scripts/power/pqse_pin_saif.py $(GLD)/pqse_top_gl.v {}/$(GL_DUMP) {}/gate_pins.saif --scope $(GL_SCOPE) > {}/pins.log 2>&1 \
	    || { echo "{}: pin mapping failed"; tail -3 {}/pins.log; exit 1; }; \
	    SKY130_LIB=$(SKY130_LIB) RAM_LIB=$(PW_RAMLIB) NETLIST=$(GLD)/pqse_top_gl.v VCD={}/gate_pins.saif SCOPE=auto \
	    $(STA) -no_splash -exit scripts/pqse_power.tcl > {}/power_gl.txt 2>&1 && echo "{}: power done" \
	    || { echo "{}: OpenSTA failed"; tail -5 {}/power_gl.txt; exit 1; }'
	$(PYTHON) scripts/power/pqse_energy.py --windows $(GLD)/win/w* $(PW_EARGS) \
	    $(if $(PW_RAMLIB),,--no-sram) | tee $(GLD)/energy_sampled$(PW_TAG).txt

# Exact robust-probing check (glitches + transitions, first order) of the
# masked gadgets' gate-level equations: DOM AND, the B2A / adder carry, the
# Keccak chi slice and the two share-recombining compare stages (OKCHK, SEQ).
se-probe:
	$(PYTHON) scripts/pqse_probe_verify.py

# ---- Platform Designer component ---------------------------------------------------
ip:
	$(PYTHON) scripts/package_ip.py 3

# ---- ARM (HPS) program -----------------------------------------------------------
SW_SRC := sw/mlkem_hps.c $(SRC)

sw-emu: | $(BUILD)
	$(CC) $(CFLAGS) -Wno-unknown-pragmas -DMLKEM_EMULATE -Isrc -Ihls $(SW_SRC) src/mlkem_accel.c \
	    -o $(BUILD)/mlkem_hps_emu
	$(BUILD)/mlkem_hps_emu -n 20

sw-arm: | $(BUILD)
	$(CROSS)gcc $(CFLAGS) -mcpu=cortex-a9 -static -Isrc -Ihls $(SW_SRC) -o $(BUILD)/mlkem_hps
	@echo "copy $(BUILD)/mlkem_hps to the board and run: sudo ./mlkem_hps"

# ---- test vectors ----------------------------------------------------------------
vectors:
	$(PYTHON) scripts/acvp_to_txt.py $(ACVP_JSON) vectors
	$(PYTHON) scripts/make_tb_vectors.py vectors/ML-KEM-768.txt hls/tb_vectors.h hw/sim/vectors

clean:
	rm -rf $(BUILD)
