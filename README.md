# PQSE: a post-quantum secure element for ML-KEM-768

PQSE is a compact, low-power secure-element core for **ML-KEM-768** (FIPS 203), written in Verilog and built side-channel- and fault-aware from the start. It targets contactless identity and digital-trust devices: ID cards, signature tokens, payment, IoT identity. There the 13.56 MHz field supplies a few milliwatts and the reader allows waiting-time extensions, so the design trades clock cycles for area and energy.

Design priorities, in order:

1. **small area**: one engine at a time under microcode, one modular multiplier and one butterfly, a lane-serial Keccak with its state in RAM;
2. **very low energy**: clock enables and gating on every pipeline, operand isolation, idle engines that do not toggle;
3. **resistance to physical attacks**:
   - **first-order masking of every secret**, with every masked gadget checked in the robust probing model with glitches and transitions;
   - **hiding**: random word orders and dummy cycles;
   - **fault detection** with a wipe-and-count response.

The complete design description is in **[`hw/se/README.md`](hw/se/README.md)**: block diagram, masked gadgets, the threat-to-countermeasure table, fault detectors, interface, register map and microcode.

---

## Contents

1. [Status](#1-status)
2. [What the chip does](#2-what-the-chip-does)
3. [Architecture in one page](#3-architecture-in-one-page)
4. [Measured results](#4-measured-results)
5. [Security measures](#5-security-measures)
6. [Install the tools](#6-install-the-tools)
7. [Run it](#7-run-it)
8. [Folder map](#8-folder-map)
9. [Scope and limits](#9-scope-and-limits)
10. [References](#10-references)

---

## 1. Status

Results of the current version (v4, branch `claude/v4-tooling`), run with Verilator 5, Yosys and OpenSTA:

| Check | Result |
|---|---|
| `make sim-se` (and `LOWPOWER=1`): NIST ACVP known answers for KeyGen and Encaps, masked Decaps (valid and implicit rejection), round trip, input checks, PUF enroll / wrap / unwrap, secure messaging, raw dumps, every injected-fault and tamper test, persistence across power cycles, the USER lifecycle rules, SPI | **TEST PASSED** |
| Independent checks run by `make sim-se`: the Python model of the gadget arithmetic, the KMAC of every sealed message (`pqse_sm_check.py`), PUF / TRNG statistics | pass |
| `make se-probe`: exhaustive first-order robust-probing check (glitches + transitions) of every masked gadget, with negative controls that must leak | **PROBING CHECK PASSED** |
| TVLA, fixed-vs-random, masked Decaps, two independent runs (`pqse_tvla.py confirm`), operand-isolated build | no confirmed first-order leakage |
| Fault-injection campaign, 200 random single-bit flips per command, 38 targets, every run a cold chip | Decaps and KeyGen: **0 silent faults, 0 hangs** |
| Gate-level power, sky130_fd_sc_hd, whole masked KeyGen | 92.5 µJ, 0.57 mW at 3.39 MHz (section 4) |

**Not yet run:** the FPGA board builds (Tang Nano 20K, DE10-Nano) with the current version, place and route, and silicon.

---

## 2. What the chip does

| Command | What it does |
|---|---|
| KEYGEN | masked ML-KEM-768 KeyGen; the key pair is checked before it is marked valid (section 5) |
| ENCAPS / DECAPS | masked Encaps / Decaps; the shared secret K stays inside, masked, as a **session key** (copied to the host only in the TEST / PERSO lifecycle) |
| SEAL / OPEN | secure messaging with the session key: KMAC256 keystream and tag (SP 800-185), 64-bit counters and a 64-message replay window |
| ENROLL, KGWRAP, UNWRAP | the secret key wrapped under a key from an on-chip **SRAM-cell PUF** (RM(1,5) fuzzy extractor with masked decoding, a key check value and majority-read retries), so no key is stored in non-volatile memory |
| IMPORT, ZEROIZE, PUFRAW, TRNGRAW | key import (personalization), wipe, raw PUF / TRNG dumps for characterization (TEST only) |

It also has a lifecycle that only moves forward (TEST → PERSO → USER → KILLED), with debug features locked by state. A tamper input wipes the keys. The security state (lifecycle, fault count, tampered flag) is kept in a persistent store.

The host interface is a 32-bit register bus behind a 4-pin SPI slave (chip), or behind Avalon-MM (FPGA demo), with a 4 KB I/O buffer. The register map and command list are in `hw/se/README.md`, section 10.

---

## 3. Architecture in one page

```
            SPI (4 pins) / Avalon-MM (FPGA)      tamper  IRQ   trigger (TEST only)
                       |                            |     ^     ^
              +--------v----------------------------v-----+-----+-----+
              |  pqse_host: CSRs, lifecycle, buffer windows, command  |
              |  policy, fault counter + watchdog, persistent state,  |
              |  power-on / fault / tamper ZEROIZE                    |
              +----------+----------------------------+---------------+
                         |                             |
              +----------v------------+    +-----------v--------------------------+
              | sequencer + microcode |    | I/O buffer 4 KB                      |
              | 1024 x 96 ROM, shadow |    +--------------------------------------+
              | pc / state, parity    |
              +--+-----+-----+----+---+
                 |     |     |    |
   +-------------v-+ +-v-------+ +v--------+ +-----------------+  +----------------------+
   | masked Keccak | | poly    | | masked  | | seed registers  |  | polynomial RAMs      |
   | lane-serial,  | | unit:   | | gadgets:| | 2 x 64 x 65     |  | 2 x 1024 x 25,       |
   | state in RAM  | | 1 mult, | | CBD,    | | (one per share) |  | one per share,       |
   | + sponge,     | | 1 BFU,  | | Compress| | + parity        |  | + parity             |
   | KMAC,         | | shuffled| | compare,| +-----------------+  +----------------------+
   | SampleNTT     | +---------+ | select  |   I/O unit             PUF + fuzzy extractor
   +---------------+             +---------+   TRNG + Trivium PRNG  Fisher-Yates shuffle
```

- **One engine at a time** under a microcoded sequencer, and every RAM port is a multiplexer on the instruction class. There is no hazard logic, idle engines don't toggle, and only one operation leaks at a time.
- **Keccak-f[1600], lane-serial**: a 64-bit datapath, with the state in two 64 × 65 RAMs, one per share (lane + parity bit). The θ column parities are kept in registers, so a round takes ~126 clocks and a permutation ~3,050. The χ is masked with DOM: 64 fresh random bits per lane.
- **NTT / INTT / pointwise multiply** on one modular multiplier and one butterfly, with each share processed separately. Every NTT layer runs in its own random order.
- **Arithmetic shares** of each polynomial live in two RAMs, share 0 in one and share 1 in the other. No RAM bus, read register or multiplexer ever holds both shares of a coefficient.

---

## 4. Measured results

**Clock cycles** (Verilator, `make sim-se LOWPOWER=1`, hiding on):

| Command | Clocks | at 3.39 MHz (13.56 MHz / 4, contactless) | at 10 MHz |
|---|---|---|---|
| KeyGen (with the pairwise test and the duplicate s / e / G) | 545,344 | 161 ms | 54.5 ms |
| KGWRAP (PUF key + KeyGen + wrap) | 587,755 | 173 ms | 58.8 ms |
| Encaps | 267,964 | 79 ms | 26.8 ms |
| Decaps (m′ decoded twice) | 298,465–304,526 | 88–90 ms | 30 ms |
| UNWRAP (PUF key right at the first read) | 271,738 | 80 ms | 27.2 ms |
| SEAL / OPEN (128 bytes) | 22,550 | 6.7 ms | 2.3 ms |
| ENROLL | 38,876 | 11.5 ms | 3.9 ms |

Without the KeyGen fault checks, KeyGen takes 242,129 clocks. The pairwise test and the second computation of s, e and G add the rest.

**Energy** (gate-level, sky130_fd_sc_hd tt 25 °C 1.8 V): the mapped, clock-gated netlist runs a whole masked KeyGen in Verilator. Toggles go to a SAIF, and OpenSTA turns them into power. The SRAM macros are counted from their access counts with an assumed energy per access. Clock tree, wires, pads and analog blocks are not included.

| KeyGen | |
|---|---|
| Energy | **92.5 µJ** (logic 71.0 µJ, SRAM 21.5 µJ) |
| Time / average power at 3.39 MHz | 162 ms / **0.57 mW** |
| Energy per clock | 168.5 pJ |
| Flip-flops (behind 269 clock gates) | 7,774 (6,622) |
| Setup slack at 50 MHz (20 ns) | 7.3 ns |

These figures predate the last two clock-gating changes. Those moved the θ column parities and the χ operands behind clock gates, about 900 flip-flops that had been clocked every cycle, so re-run `make se-power-vcd` for current figures.

---

## 5. Security measures

**Side channels**
- **Masking of every secret.** KeyGen, Encaps and Decaps run entirely on two shares: the TRNG seeds, s, e, y, the NTT / PWM / INTT per share, G / J / PRF / KMAC on the masked Keccak, the masked CBD and the masked Compress. m′, K and the comparison result are never unmasked.
- **Masked Decaps comparison.** c′ = c is checked bit by bit in shares, and the implicit-rejection select is masked.
- **Verified gadgets.** Every gadget is checked exhaustively against first-order probes, glitches and transitions (`make se-probe`).
- **Hiding:**
  - constant time;
  - a fresh uniformly random order for every shuffled instruction (Fisher–Yates) and for every NTT layer;
  - 0–15 random dummy clocks before every engine start.
- **Leakage test (TVLA).** A register-level TVLA (`make sim-se-tvla`) runs in simulation, and a board capture flow (`quartus/jtag/pqse_tvla_capture.tcl`, `pqse_tvla.py board`) covers real traces.

**Faults** (any detection aborts with result FAULT; the host resets the engines, wipes all keys and counts the fault; the third fault → KILLED)
- **Decaps:** two independently masked copies of the comparison result; m′ decoded twice and compared share-wise.
- **Control flow:** program counter, sequencer state and every Keccak and sponge control register have a complemented shadow, and instructions carry parity. An engine-ran check catches a suppressed engine start, and a host watchdog ends hung commands.
- **Storage:** parity on every RAM word (polynomial, seed, Keccak state) and on the θ column parities.
- **PRNG:** a hardware check that no random word is used twice.
- **KeyGen:**
  - every secret polynomial is computed twice with fresh masks and compared share-wise (`ZCHK`), and so is G(d‖3);
  - then a FIPS 140-3 pairwise consistency test (Encaps to the new ek, Decaps with the new key, K compared) runs before the key is marked valid.
- **Security state:** lifecycle, fault counter and tampered flag have complemented shadows, are kept in a persistent store written ahead of every change, and are checked for rollback.

The fault campaign (`make sim-se-fault`) flips one random bit in one of 38 targets at a random clock of a NIST-vector command. It sorts the outcomes into unchanged, detected, implicit rejection, SILENT and hang. Current result: no silent fault and no hang, for both Decaps and KeyGen.

**Keys at rest:** no long-term key in non-volatile memory. The secret key is wrapped under a PUF-derived key, and the PUF key is reconstructed masked.

---

## 6. Install the tools

Linux or WSL2. The simulations need only the first two items:

| Tool | For | Notes |
|---|---|---|
| **Verilator ≥ 5** | all simulations | 5.036 or newer for SAIF output (`se-power-vcd`) |
| **Python 3** | models, checks, reports | standard library; numpy speeds up `pqse_model.py` and is needed for the board TVLA mode |
| **Yosys** | `se-area`, `se-power*`, `se-gowin`, `se-probe` netlists | the OSS CAD Suite bundle has Yosys and Verilator |
| **OpenSTA** | `se-power`, `se-power-vcd` | not part of OSS CAD Suite; or use OpenROAD (`make se-power STA=openroad`) |
| **sky130_fd_sc_hd liberty** | the power flows | `SKY130_LIB=<path to sky130_fd_sc_hd__tt_025C_1v80.lib>` |
| Gowin EDA (optional) | `se-gowin-eda`: vendor synthesis + place & route for the Tang Nano 20K | |
| Quartus Prime Lite (optional) | DE10-Nano demo (`quartus/jtag`, `build.tcl se`) | |

The NIST ACVP test vectors are checked in (`hw/sim/vectors`). `make vectors` regenerates them from the ACVP JSON files.

---

## 7. Run it

In this order:

```bash
make sim-se                       # Python model + probing checks, RTL testbench, KMAC check, PUF/TRNG stats
make sim-se LOWPOWER=1            # the same on the operand-isolated ASIC variant
make sim-se TRACE=1               # + every microcode instruction and which detector fired

make se-probe                     # robust-probing check of the masked gadgets alone
make sim-se-tvla N=200            # TVLA of the masked Decaps (MASKED=0: positive control, must leak)
make sim-se-tvla N=200 SEED=2     # second independent run, then:
python3 scripts/pqse_tvla.py confirm build/tvla_m1_s1/tvla_t.txt build/tvla_m1_s2/tvla_t.txt

make sim-se-fault FN=200          # fault campaign on Decaps (FOP=keygen for KeyGen): expect no SILENT
make sim-se-fault FN=200 FMODE=chain   # chip state carried from run to run (finds effects that survive a reset)

make se-area                      # Yosys cell count (SKY130_LIB=... maps to sky130)
make se-power SKY130_LIB=... RAM_MACRO=1        # vectorless power, slowest path, flip-flops still clocked every cycle
make se-power-vcd SKY130_LIB=... RAM_MACRO=1    # energy per KeyGen from a gate-level run (GL_CMD=2: Encaps)
make se-gowin                     # fit on the Tang Nano 20K (GW2AR-18), largest modules
cd quartus/jtag && quartus_sh -t build.tcl se   # DE10-Nano demo, then source pqse_test.tcl in System Console
```

`hw/se/README.md` section 13 has the bring-up order and what to check when a step fails.

---

## 8. Folder map

```
hw/se/                    the secure element (Verilog), README.md = full design description
  pqse_top.v                chip top (SPI, IRQ, tamper, trigger), Avalon wrapper, system
  pqse_host.v               CSRs, lifecycle, policy, fault counter, watchdog, persistent state
  pqse_core.v               sequencer, RAMs with parity, TRNG / PRNG, port multiplexing
  pqse_ucode.v              microcode: KeyGen (+ checks), Encaps, Decaps, PUF, wrap, SEAL / OPEN, ...
  pqse_keccak.v, pqse_sponge.v   masked lane-serial Keccak, sponge / KMAC / sinks
  pqse_poly.v, pqse_perm.v       NTT / INTT / PWM / ADD / SUB / ZCHK, Fisher-Yates shuffle
  pqse_masked.v, pqse_mcomp.v    masked CBD, mu, select, ok copies, masked Compress
  pqse_io.v, pqse_sample.v       encode / decode, seed ops, replay window; SampleNTT
  pqse_puf.v, pqse_rng.v         PUF + fuzzy extractor; TRNG + health tests, Trivium PRNG
hw/sim/                   tb_pqse.sv (functional), tb_pqse_tvla.sv, tb_pqse_fault.sv,
                          tb_pqse_gate.sv (gate-level power), vectors/ (NIST ACVP, hex)
scripts/                  pqse_model.py, pqse_probe_verify.py, pqse_tvla.py, pqse_fault_report.py,
                          pqse_sm_check.py, pqse_puf_stats.py, pqse_fit.py, pqse_power.tcl
scripts/power/            SRAM macro models, SAIF pin mapping, energy report, flip-flop report
gowin/                    Gowin EDA flow (Tang Nano 20K)
quartus/jtag/             DE10-Nano top, System Console demo, TVLA capture
Makefile                  all flows above (make help)
```

---

## 9. Scope and limits

- **Masking order.** First-order masking plus hiding, the usual trade-off for smart-card-class area and power. Higher-order masking would cost ~3–4× in area and time.
- **What the checks cover.** The probing check and the register-level TVLA work at the level of the RTL registers and schedule. What synthesis does to the netlist and the coupling inside SRAM macros need the board TVLA or a netlist-level check (e.g. PROLEAD).
- **Energy figures.** The energy is from a gate-level simulation without clock tree, wires or analog blocks. The SRAM energy per access is an assumption, documented in `scripts/power/pqse_energy.py`.
- **FPGA PUF and TRNG.** On the FPGA these demonstrate the interfaces and the post-processing. A chip uses characterized PUF cells and TRNG macros, and replaces the persistent-store model with its OTP / eFuse macro.
- **Possible extension:** ML-DSA (FIPS 204) signatures on the same Keccak and polynomial datapath.

---

## 10. References

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (ML-KEM), 2024.
- NIST FIPS 202 (SHA-3) and SP 800-185 (cSHAKE, KMAC).
- NIST ACVP test vectors for ML-KEM (`hw/sim/vectors`).
- NIST FIPS 140-3 (ISO/IEC 19790): pairwise consistency test for generated key pairs.
- H. Groß, S. Mangard, T. Korak, *Domain-Oriented Masking: Compact Masked Hardware Implementations with Arbitrary Protection Order*, TIS 2016.
- S. Faust, V. Grosso, S. Merino Del Pozo, C. Paglialonga, F.-X. Standaert, *Composable masking schemes in the presence of physical defaults & the robust probing model*, TCHES 2018.
- G. Goodwill et al., *A testing methodology for side-channel resistance validation* (TVLA), NIST NIAT 2011.
- P. Pessl, R. Primas, *More practical single-trace attacks on the number theoretic transform*, Latincrypt 2019; R. Primas et al., *Single-trace side-channel attacks on masked lattice-based encryption*, CHES 2017.
