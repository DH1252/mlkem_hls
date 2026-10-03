# PQSE: a post-quantum secure element for ML-KEM-768

PQSE is a secure-element core written in Verilog. A secure element is the small chip in a bank card, passport or SIM that stores keys and does the cryptography itself, built to hold up against an attacker who has the device in hand. PQSE runs ML-KEM-768, the key-exchange algorithm NIST standardized in 2024 (FIPS 203) to replace RSA and elliptic curves, which a large quantum computer would break.

The target is a contactless card. The reader's 13.56 MHz field powers the chip with a few milliwatts, and the reader waits if the card asks for more time, so the design spends clock cycles to save area and energy. The goals, in order, are small area, low energy per operation, and resistance to physical attacks: measuring the chip's power or electromagnetic emission (side-channel attacks) and disturbing it with glitches or a laser (fault attacks).

| Document | Read it for |
|---|---|
| [`docs/PQSE_design.md`](docs/PQSE_design.md) | the design: a plain-language part, then the engineering description |
| [`hw/se/README.md`](hw/se/README.md) | the RTL reference: registers, commands, microcode map, detectors, testbenches, debugging |
| [`docs/proposal_hackathon_chip_2026.md`](docs/proposal_hackathon_chip_2026.md) | proposal text for the Hackathon Chip 2026 (in Indonesian) |

## Status

Version 4, branch `claude/v4-tooling`, checked with Verilator 5, Yosys and OpenSTA.

| Check | Result |
|---|---|
| Functional testbench (`make sim-se`, also `LOWPOWER=1`): NIST known-answer vectors, every command, lifecycle rules, persistence across power cycles, 17 directed fault and tamper tests, SPI | pass |
| Probing check of every masked gadget (`make se-probe`) | pass |
| TVLA leakage test on masked Decaps, two independent runs | no confirmed first-order leakage |
| Fault campaign: 200 random single-bit flips per command over 38 targets | Decaps and KeyGen: 0 silent faults, 0 hangs |
| Gate-level energy of one KeyGen, SkyWater 130 nm | 74 to 90 µJ, 0.45 to 0.55 mW average at 3.39 MHz |

The probing check simulates each masked circuit clock by clock and confirms that no single probed wire, even with glitches and the value it held one clock earlier, depends on a secret. TVLA (test vector leakage assessment) compares simulated power traces for a fixed input against traces for random inputs with a t-test. A silent fault is a flipped bit that changes the result without the chip noticing, which is what a fault attacker needs.

Not yet done with this version: the FPGA board builds, place and route, and silicon.

## What the chip does

| Command | Function |
|---|---|
| KEYGEN | Makes an ML-KEM key pair. The key pair is checked before it is marked valid. |
| ENCAPS, DECAPS | The two halves of a key exchange. The 32-byte shared secret K stays inside the chip as the session key. |
| SEAL, OPEN | Encrypt and authenticate messages of 1 to 128 bytes with the session key, using KMAC256 (a keyed SHA-3 mode, SP 800-185). Replayed messages are rejected. |
| ENROLL, KGWRAP, UNWRAP | Store the secret key encrypted under a key that comes from the chip's PUF, so no key sits in non-volatile memory. |
| IMPORT, ZEROIZE | Load a key during personalization; wipe all keys. |
| PUFRAW, TRNGRAW | Raw PUF and random-number-generator dumps for characterization (test state only). |

A PUF (physically unclonable function) is a circuit whose output comes from random manufacturing differences, so every chip produces its own stable bit pattern. Data wrapped under that pattern is useless on another chip.

The chip has a lifecycle that only moves forward: TEST, PERSO (personalization), USER, KILLED. Debug features work only in TEST. A tamper input wipes the keys and moves the chip to KILLED. The lifecycle, the fault count and the tamper flag are kept in a persistent store.

The host sees a 32-bit register bus and a 4 KB I/O buffer, reached through a 4-pin SPI slave on the chip or Avalon-MM on the FPGA demo.

## How it works

```
            SPI (4 pins) / Avalon-MM (FPGA)      tamper  IRQ   trigger (TEST only)
                       |                            |     ^     ^
              +--------v----------------------------v-----+-----+-----+
              |  pqse_host: registers, lifecycle, buffer windows,     |
              |  command policy, fault counter, watchdog,             |
              |  persistent state, wipe on power-on / fault / tamper  |
              +----------+----------------------------+---------------+
                         |                             |
              +----------v------------+    +-----------v--------------------------+
              | sequencer + microcode |    | I/O buffer 4 KB                      |
              | ROM 1024 x 96         |    +--------------------------------------+
              +--+-----+-----+----+---+
                 |     |     |    |
   +-------------v-+ +-v-------+ +v--------+ +-----------------+  +----------------------+
   | masked Keccak | | poly    | | masked  | | seed RAMs       |  | polynomial RAMs      |
   | state in RAM, | | unit:   | | gadgets | | 2 x 64 x 65     |  | 2 x 1024 x 25        |
   | sponge, KMAC, | | 1 mult, | |         | | (one per share) |  | (one per share)      |
   | SampleNTT     | | 1 BFU   | |         | +-----------------+  +----------------------+
   +---------------+ +---------+ +---------+   I/O unit             PUF + fuzzy extractor
                                               TRNG + PRNG          random-order shuffler
```

A microcoded sequencer starts one engine at a time and waits for it to finish. With a single active engine, every RAM port is a plain multiplexer with no arbitration, idle engines stay still, and the power trace shows one operation at a time.

Keccak is the permutation inside SHA-3 and SHAKE, which ML-KEM uses for hashing and for generating its random-looking values. PQSE computes it one 64-bit lane per clock, with the 1,600-bit state in two small RAMs instead of flip-flops. One permutation takes about 3,050 clocks.

Polynomial products use the number-theoretic transform (NTT), a fast Fourier transform over integers mod 3329. One modular multiplier and one butterfly unit (BFU) handle the forward transform, the inverse transform and pointwise multiplication.

Every secret is masked: split into two random shares whose sum (or XOR) is the secret, so each share alone is noise. Share 0 and share 1 live in different RAMs, so no RAM bus or read register ever holds both shares of one value.

## Security measures

**Side channels.** KeyGen, Encaps and Decaps run entirely on shares: the seeds, the secret polynomials, the Keccak calls on secret data, and the decoding and comparison inside Decaps. The decoded message m′, the shared secret K and the result of the ciphertext comparison are never unmasked. Where shares must interact (an AND gate on secret bits), the circuits follow domain-oriented masking (DOM): fresh random bits and a register stage keep the two shares apart. On top of masking, the chip processes words in a fresh random order for every shuffled instruction and every NTT layer, inserts 0 to 15 random dummy clocks before each engine start, and takes the same time whatever the secret.

**Faults.** Any detector ends the command with result FAULT. The host then resets the engines, wipes every key and counts the fault; the third fault moves the chip to KILLED. The detectors:

- complemented copies of the program counter, the sequencer state and the Keccak and sponge control registers, plus parity on every instruction;
- parity on every RAM word and on the Keccak column-parity registers;
- in Decaps, two independently masked copies of the comparison result, and m′ decoded twice and compared;
- a check that no random mask word is used twice, and a host watchdog for hung commands;
- in KeyGen, every secret polynomial and the seed expansion G(d‖3) computed twice with fresh masks and compared, then a pairwise consistency test (encapsulate to the new public key, decapsulate with the new secret key, compare the two shared secrets) before the key is marked valid;
- complemented copies of the lifecycle, the fault counter and the tamper flag, kept in a persistent store that is written before any further command runs.

**Keys at rest.** No long-term key is stored in non-volatile memory. The secret key is wrapped under a key derived from the PUF, and the PUF key is reconstructed in masked form.

## Measured results

Clock cycles from `make sim-se LOWPOWER=1` with hiding on:

| Command | Clocks | at 3.39 MHz (contactless, 13.56 MHz / 4) | at 50 MHz (FPGA) |
|---|---|---|---|
| KeyGen, with its fault checks | 545,344 | 161 ms | 10.9 ms |
| KGWRAP (PUF key, KeyGen, wrap) | 587,755 | 173 ms | 11.8 ms |
| Encaps | 267,964 | 79 ms | 5.4 ms |
| Decaps | 298,465 to 304,526 | 88 to 90 ms | 6.0 to 6.1 ms |
| UNWRAP (PUF key right at the first read) | 271,738 | 80 ms | 5.4 ms |
| SEAL or OPEN, 128 bytes | 22,550 | 6.7 ms | 0.45 ms |
| ENROLL | 38,876 | 11.5 ms | 0.78 ms |

KeyGen without its fault checks takes 242,129 clocks. The pairwise consistency test and the second computation of the secret polynomials and of G account for the rest.

Energy comes from a gate-level simulation: Yosys maps the RTL to sky130_fd_sc_hd cells (typical corner, 25 °C, 1.8 V) with automatic clock gating, Verilator runs a whole masked KeyGen on that netlist and records every net's toggles, and OpenSTA turns the toggles into power. SRAM energy is the access count times an energy per access, which is not yet SPICE-characterized, so the table gives two values: one assumed (a fixed cost plus a cost per bit) and one from OpenRAM's analytical model of each RAM shape. Clock tree, wires, pads and analog blocks are not included.

| KeyGen, gate level | SRAM assumed | SRAM from OpenRAM analytical model |
|---|---|---|
| Energy | 73.5 µJ | 89.9 µJ |
| of which logic | 52.0 µJ | 52.0 µJ |
| of which SRAM | 21.5 µJ (29 %) | 37.9 µJ (42 %) |
| Average power over the 162 ms run at 3.39 MHz | 0.45 mW | 0.55 mW |
| Energy per clock | 133.8 pJ | 163.7 pJ |

| Netlist | |
|---|---|
| Flip-flops | 7,775, of which 7,526 (97 %) sit behind 285 clock gates |
| Setup slack at 20 ns (50 MHz) | 7.2 ns |

Giving the last ~900 flip-flops that were clocked every cycle a proper enable took KeyGen from 92.5 to 73.5 µJ (with the assumed SRAM energy). The two SRAM estimates agree for the Keccak-state and seed RAMs (19.2 and 17.6 µJ) and disagree for the 1024 x 25 polynomial RAM: 2.2 µJ assumed against 19.8 µJ analytical, 162 pJ per access, because its long bitlines cost far more than the per-bit assumption. That RAM is the main uncertainty; a SPICE run of its shape (`make se-sram-char SRAM_SHAPES=a10_d25`, see `hw/se/README.md`, section 4) settles it. SRAM leakage is negligible at 25 °C (under 0.5 µJ per KeyGen by estimate).

## Install the tools

Linux or WSL2. The simulations need only Verilator and Python.

| Tool | Used by | Notes |
|---|---|---|
| Verilator 5 | all simulations | 5.036 or newer to write SAIF activity files (`se-power-vcd`) |
| Python 3 | models, checks, reports | standard library; numpy speeds up `pqse_model.py` and is needed for board TVLA |
| Yosys | `se-area`, `se-power*`, `se-gowin`, `se-probe` | the OSS CAD Suite bundle has Yosys and Verilator |
| OpenSTA | `se-power`, `se-power-vcd` | not in OSS CAD Suite; OpenROAD works too (`STA=openroad`) |
| sky130_fd_sc_hd Liberty file | the power flows | pass `SKY130_LIB=<path to sky130_fd_sc_hd__tt_025C_1v80.lib>` |
| OpenRAM, ngspice (optional) | `se-sram-char` | SRAM energy from SPICE |
| Gowin EDA (optional) | `se-gowin-eda` | vendor synthesis and place and route for the Tang Nano 20K |
| Quartus Prime Lite (optional) | DE10-Nano demo | `quartus/jtag`, `build.tcl se` |

The NIST ACVP test vectors are checked in under `hw/sim/vectors`; `make vectors` regenerates them from the ACVP JSON files.

## Run it

```bash
make sim-se                       # Python model and probing checks, RTL testbench, KMAC check, PUF/TRNG stats
make sim-se LOWPOWER=1            # the same on the operand-isolated ASIC variant
make sim-se TRACE=1               # also prints every microcode instruction and which detector fired

make se-probe                     # probing check of the masked gadgets alone
make sim-se-tvla N=200            # TVLA of masked Decaps (MASKED=0 is the positive control and must leak)
make sim-se-tvla N=200 SEED=2     # second independent run, then:
python3 scripts/pqse_tvla.py confirm build/tvla_m1_s1/tvla_t.txt build/tvla_m1_s2/tvla_t.txt

make sim-se-fault FN=200          # fault campaign on Decaps (FOP=keygen for KeyGen); expect no SILENT
make sim-se-fault FN=200 FMODE=chain   # chip state carried from run to run

make se-area                      # Yosys cell count (SKY130_LIB=... maps to sky130)
make se-power SKY130_LIB=... RAM_MACRO=1        # vectorless power and the slowest path
make se-power-vcd SKY130_LIB=... RAM_MACRO=1    # energy of one KeyGen from a gate-level run (GL_CMD=2: Encaps)
make se-gowin                     # fit report for the Tang Nano 20K (GW2AR-18)
cd quartus/jtag && quartus_sh -t build.tcl se   # DE10-Nano demo, then source pqse_test.tcl in System Console
```

`hw/se/README.md` section 16 gives the bring-up order and what to check when a step fails.

## Folder map

```
hw/se/                    the secure element (Verilog); README.md is the RTL reference
  pqse_top.v                chip top (SPI, IRQ, tamper, trigger), Avalon wrapper
  pqse_host.v               registers, lifecycle, policy, fault counter, watchdog, persistent state
  pqse_core.v               sequencer, RAMs with parity, TRNG / PRNG, port multiplexing
  pqse_ucode.v              microcode: KeyGen and its checks, Encaps, Decaps, PUF, wrap, SEAL / OPEN
  pqse_keccak.v, pqse_sponge.v   masked lane-serial Keccak; sponge, KMAC, output sinks
  pqse_poly.v, pqse_perm.v       NTT / INTT / PWM / ADD / SUB / ZCHK; random-order shuffler
  pqse_masked.v, pqse_mcomp.v    masked sampler, select, comparison copies; masked Compress
  pqse_io.v, pqse_sample.v       encode / decode, seed operations, replay window; SampleNTT
  pqse_puf.v, pqse_rng.v         PUF and fuzzy extractor; TRNG with health tests, Trivium PRNG
hw/sim/                   tb_pqse.sv (functional), tb_pqse_tvla.sv, tb_pqse_fault.sv,
                          tb_pqse_gate.sv (gate-level power), vectors/ (NIST ACVP)
scripts/                  models, probing check, TVLA, fault report, KMAC check, PUF stats, fit report
scripts/power/            SRAM macro models, OpenRAM configs, SAIF pin mapping, energy and flip-flop reports
docs/                     design document, hackathon proposal
gowin/                    Gowin EDA flow (Tang Nano 20K)
quartus/jtag/             DE10-Nano top, System Console demo, TVLA capture
Makefile                  every flow above (make help)
```

## Limits

- First-order masking plus hiding is the usual choice for smart-card area and power budgets. Second-order masking would cost roughly 3 to 4 times the area and time.
- The probing check and the simulated TVLA work on the RTL registers and schedule. They can't see what synthesis does to the netlist or coupling inside SRAM macros. A board TVLA or a netlist-level tool such as PROLEAD covers that.
- The energy numbers leave out the clock tree, wires and analog blocks, and the SRAM part rests on an assumed energy per access until the OpenRAM characterization replaces it.
- On the FPGA, the PUF and the ring-oscillator TRNG only demonstrate the interfaces and post-processing. A chip would use characterized PUF cells and TRNG macros, and an OTP or eFuse macro in place of the persistent-store model.
- A possible extension is ML-DSA (FIPS 204) signatures on the same Keccak and polynomial hardware.

## References

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.
- NIST FIPS 202 (SHA-3) and SP 800-185 (cSHAKE, KMAC).
- NIST ACVP test vectors for ML-KEM (`hw/sim/vectors`).
- NIST FIPS 140-3 (ISO/IEC 19790), pairwise consistency test for generated key pairs.
- H. Groß, S. Mangard, T. Korak, *Domain-Oriented Masking: Compact Masked Hardware Implementations with Arbitrary Protection Order*, TIS 2016.
- S. Faust, V. Grosso, S. Merino Del Pozo, C. Paglialonga, F.-X. Standaert, *Composable Masking Schemes in the Presence of Physical Defaults & the Robust Probing Model*, TCHES 2018.
- G. Goodwill et al., *A Testing Methodology for Side-Channel Resistance Validation* (TVLA), NIST NIAT 2011.
- R. Primas, P. Pessl, S. Mangard, *Single-Trace Side-Channel Attacks on Masked Lattice-Based Encryption*, CHES 2017; P. Pessl, R. Primas, *More Practical Single-Trace Attacks on the Number Theoretic Transform*, Latincrypt 2019.
