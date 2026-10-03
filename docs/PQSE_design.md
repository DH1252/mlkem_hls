# PQSE: a post-quantum secure element. Design document

This document is written for two audiences:

- **Part A** explains, without assuming any hardware or cryptography background, what the chip is for, what it protects against and how.
- **Part B** is the engineering description: architecture, microarchitecture of every block, memories, clocking and reset, side-channel and fault countermeasures, verification, measured area / timing / energy, and what an implementation (FPGA or ASIC) needs.

The source is in `hw/se/`. The reference description, with register map, microcode and bring-up notes, is [`hw/se/README.md`](../hw/se/README.md).

---

# Part A: in plain language

## A.1 What problem does it solve?

Every time a phone, an ID card or a payment terminal opens a secure connection, the two sides first agree on a secret key that nobody listening can learn. Today this is done with mathematics (RSA, elliptic curves) that a large **quantum computer** would break. Data recorded today could be decrypted later ("harvest now, decrypt later"). In 2024, the US standards body NIST published a replacement that quantum computers are not known to break: **ML-KEM** (FIPS 203), also known as Kyber.

ML-KEM is heavier than the old methods: keys of about 1–2 KB instead of 32–64 bytes, and many more arithmetic operations. A small battery-less device such as a contactless card struggles to run it in software, and software leaks secrets through its power consumption.

## A.2 What is a "secure element"?

A secure element is the small, hardened chip inside a bank card, an e-passport or a SIM. It keeps keys that never leave it, does the cryptography itself, and is designed to resist an attacker who has the chip in their hands. Such an attacker can:

- **measure its power consumption or electromagnetic emission** while it computes, and use statistics to recover the key (a *side-channel attack*);
- **disturb it** with a voltage glitch, a clock glitch or a laser pulse, so it makes a mistake that reveals the key (a *fault attack*);
- **probe its interface** for debug features or commands that leak something.

**PQSE** is such a chip, designed for ML-KEM-768. It is a design (Verilog RTL) that runs on an FPGA today and is intended for fabrication as a chip.

## A.3 What can it do?

- **Make a key pair** (KeyGen), **create a shared secret for someone else's public key** (Encaps), and **recover a shared secret sent to it** (Decaps). These are the three ML-KEM operations.
- **Keep the shared secret inside** as a *session key* and use it to **encrypt and authenticate messages** (SEAL / OPEN). The secret never has to leave the chip.
- **Store its long-term key without non-volatile memory.** The key is encrypted ("wrapped") under a key the chip derives from its own silicon fingerprint, a **PUF** (physically unclonable function: tiny random manufacturing differences that make every chip unique). A copy of the stored data is useless on another chip.
- **Know its lifecycle:**
  - *test*: open for manufacturing tests;
  - *personalization*: keys are loaded;
  - *user*: in the field, locked;
  - *killed*: permanently disabled.

  It can only move forward through these states.

## A.4 How does it protect the secrets?

| Attack | How the chip defends itself, in one sentence |
|---|---|
| Listening to power / EM | **Masking.** Every secret is split into two random halves that are processed separately; each half alone is pure noise, and the halves are never combined. |
| Same, with many measurements | **Hiding.** The order of the operations is shuffled at random every time and random pauses are inserted, so measurements don't line up. |
| Timing | Every operation takes the same time whatever the secret. |
| Glitches, laser | **Self-checks.** Important values are computed twice and compared, control registers have inverted twins, memories carry a check bit, and the new key is test-used before release. On any mismatch the chip wipes its keys, and after three such events it disables itself for good. |
| Tampering with the package | A tamper input wipes everything and kills the chip. |
| Stealing the stored key | The stored key is encrypted under the chip's own fingerprint (PUF). |
| Abusing debug features | Debug and test functions exist only in the test state; the lifecycle cannot go back. |

## A.5 How do we know it works?

- **Correct:** it reproduces the official NIST test vectors for ML-KEM.
- **Leakage-free in simulation:** a standard leakage test (TVLA) on simulated power traces finds no first-order leakage, and every masking building block passes a mathematical check that covers glitches.
- **Fault-tolerant:** in 400 simulated random fault injections (one flipped bit each, anywhere in the chip, at any moment) the chip never gave a wrong result without noticing. A few faults ended in the designed safe outcome, a random-looking key instead of an error.
- **Small and frugal:** a key generation takes about 0.16 s at the 3.4 MHz clock a contactless reader provides. Its energy is about 75 µJ, an average of about 0.45 mW, which a reader's field can supply.

---

# Part B: engineering description

## B.1 Specification summary

| Item | Value |
|---|---|
| Algorithm | ML-KEM-768 (FIPS 203): KeyGen, Encaps, Decaps (with implicit rejection); SHA3-256/512, SHAKE128/256 (FIPS 202); KMAC256 (SP 800-185) |
| Object sizes | ek 1,184 B, dk 2,400 B (kept internally as masked ŝ, H(ek), z), ciphertext 1,088 B, shared secret 32 B |
| Commands | KEYGEN, ENCAPS, DECAPS, IMPORT, ENROLL, KGWRAP, UNWRAP, ZEROIZE, SEAL, OPEN, PUFRAW, TRNGRAW |
| Host interface | 32-bit register bus (CSRs + 4 KB I/O buffer), read latency 1; SPI slave mode 0 (chip), Avalon-MM (FPGA) |
| Pins (chip) | clk, rst_n, SPI (4), IRQ, tamper in, trigger out (lifecycle TEST only) |
| Clock | single clock domain; design point 50 MHz (FPGA), 3.39 MHz (13.56 MHz / 4, contactless) |
| Reset | asynchronous assert, synchronous release (`pqse_top`), synchronous reset inside |
| Side-channel protection | first-order Boolean / arithmetic masking of every secret, DOM gadgets, robust-probing verified; hiding (shuffling + dummy cycles); constant time |
| Fault protection | duplication + compare, complemented shadows, parity, control-flow checks, watchdog, PRNG freshness check, KeyGen duplicate computation + pairwise consistency test; wipe-and-count response, KILLED after 3 faults |
| Entropy | ring-oscillator TRNG with SP 800-90B health tests → SHA3-256 conditioning; Trivium PRNG (masks), reseeded per command |
| Key storage | PUF (960 SRAM-type cells, RM(1,5) code-offset fuzzy extractor, masked decoding) → KEK; wrapped-key blob |
| Persistent state | lifecycle, fault counter, tampered flag in a set-only store (OTP / eFuse semantics) |

## B.2 Top-level architecture

```
                 SPI / Avalon-MM            tamper   IRQ   trigger
                       |                       |      ^      ^
   +-------------------v-----------------------v------+------+------+
   | pqse_host                                                      |
   |  CSRs, lifecycle FSM (+ complemented shadows), buffer windows, |
   |  command policy, K-export policy, fault counter, watchdog,     |
   |  persistent store (pqse_nvm), power-on / fault / tamper wipe   |
   +-----------+-----------------------------------+----------------+
               | cmd, start / done, result          | host buffer port (idle only)
   +-----------v-----------------------------------v----------------+
   | pqse_core                                                      |
   |  sequencer: 1024 x 96 microcode ROM (registered read), pc+~pc, |
   |  state + ~state, instruction parity, engine-ran check          |
   |                                                                |
   |  engines (one active at a time, started by the sequencer):     |
   |   pqse_sponge + pqse_keccak   masked SHA-3 / SHAKE / KMAC      |
   |   pqse_poly                   NTT / INTT / PWM / ADD / SUB /   |
   |                               MSPLIT / ZERO / ZCHK             |
   |   pqse_masked + pqse_mcomp    masked CBD (B2A), mu, Compress,  |
   |                               compare, select, ok copies       |
   |   pqse_io                     encode / decode, seed ops, SEQ,  |
   |                               message header, replay window    |
   |   pqse_puf                    PUF read, fuzzy extractor        |
   |   pqse_parse                  SampleNTT (rejection sampling)   |
   |  support: pqse_trng, pqse_prng (Trivium), pqse_perm            |
   |  (Fisher-Yates)                                                |
   |  memories: polynomial RAM 0/1 (2 x 1024 x 25), seed RAM 0/1    |
   |   (2 x 64 x 65), Keccak state RAM 0/1 (2 x 64 x 65),           |
   |   I/O buffer (2 x 512 x 32), shuffle table (128 x 7, 2R1W)     |
   +----------------------------------------------------------------+
```

**Execution model.** A microcoded sequencer runs one instruction at a time: fetch, an optional permutation draw (hiding), optional dummy clocks, execute, wait until the engine is done. Only one engine is ever active, so:

- every RAM port is a plain multiplexer selected by the instruction class, with no arbitration or hazard logic;
- idle engines hold still, which keeps power and peak current low;
- only one operation contributes to the power trace at any time.

Speed is deliberately traded for area and energy: the target clock of a contactless card is 3.39 MHz, and the reader grants waiting-time extensions.

**Instruction classes** (96-bit word): `END`, `BR` (branch on a flag), `SET` (status flags, reseed), `HASH` (a complete sponge job: sources, padding, rate, masked or not, sink), `POLY`, `IO`, `MASK`, `PUF`. One ML-KEM operation is a few hundred instructions. Programs live at fixed ROM addresses: KeyGen 16 / 80, Encaps 192, Decaps 320, KeyGen checks 720, pairwise test 608, and so on.

## B.3 Data representation and memories

| Memory | Organisation | Content | Implementation |
|---|---|---|---|
| Polynomial RAM 0 / 1 | 1024 × 25 each (two 12-bit coefficients + parity per word, 16 slots of 128 words) | even slots in RAM 0 (share 0 and public), odd slots in RAM 1 (share 1) | M10K on Cyclone V; SRAM macro on ASIC |
| Seed RAM 0 / 1 | 64 × 65 each (64-bit lane + parity, 16 entries of 4 lanes) | Boolean shares of seeds and keys: d, z, m, K, ρ, σ, session key, KEK, … | LUTRAM / MLAB; register file or SRAM |
| Keccak state RAM 0 / 1 | 64 × 65 each | the 25 lanes of each share, the ρπ output, parity | M10K; SRAM macro |
| I/O buffer | 2 × 512 × 32 (4 KB) | ek, ciphertexts, helper data, blob, messages | M10K; SRAM macro |
| Microcode ROM | 1024 × 96, registered read | the programs | M10K ROM; ROM / logic |
| Shuffle table | 128 × 7, 2 reads + 1 write | Fisher–Yates permutation | MLAB; register file |

**Share separation.** The two shares of a secret are kept in different RAMs throughout: share 0 in RAM 0, share 1 in RAM 1, for polynomials, seeds and the Keccak state alike. A RAM's read register, bus or output multiplexer therefore never holds both shares of one value. Between instructions the sequencer precharges both polynomial-RAM output registers: in its fetch clocks it reads an all-zero slot from RAM 1 and a public word from RAM 0. That way the first read of an instruction never follows the other share of the same coefficient.

## B.4 Masked Keccak (`pqse_keccak.v`, `pqse_sponge.v`)

- **Lane-serial datapath**, 64 bits wide, with the state in RAM (one RAM per share, one read and one write per clock). A round has passes θ+ρ+π (RP) and χ+ι (CHI). The θ column parities C[x] are kept in registers and accumulated by the χ write-back, so only round 0 needs a separate θ parity pass. Round 0 takes 162 clocks and every later round about 126, about **3,050 clocks per permutation**.
- **χ is masked with DOM:** X = ¬a[x+1] and Y = a[x+2] are loaded one lane each, then one DOM AND with 64 fresh random bits per lane, then write-back. X and Y hold their values only in their slot clocks and are cleared after the AND, so the AND never sees both shares of a lane, not even across consecutive clocks. This schedule is what `make se-probe` verifies, together with a negative control.
- **Fault detection:** a parity bit on every state word and on each column-parity register, checked on use per share. The pass, round, column, plane and lane counters have complemented shadows written in the same statements; a mismatch raises a fault.
- **Sponge:** sources are seed entries (masked), buffer lanes (public) and TRNG words. Rates are 168 / 136 / 72 bytes with SHA-3 / SHAKE / cSHAKE padding and KMAC framing. Sinks are seed entries (write or XOR), SampleNTT, the masked CBD, the masked compare and the message keystream. A masked job feeds public data into share 0 only.

## B.5 Polynomial unit (`pqse_poly.v`, `pqse_arith.v`, `pqse_perm.v`)

- **One modular multiplier** (12 × 12, Barrett reduction with 5039 = ⌊2²⁴/q⌋, 4-stage pipeline) and **one butterfly**:
  - NTT / INTT: one butterfly per clock, 7 layers, about 970 clocks per transform;
  - PWM (base-case multiplication of FIPS 203 Alg. 11/12): one coefficient pair per 6 clocks, about 780 clocks;
  - ADD / SUB: one word per 2 clocks.
- **Per share:** NTT, INTT and PWM run on each share separately (they are linear). Only the public t̂ is ever recombined.
- **MSPLIT** turns an imported key into two arithmetic shares. **ZCHK** checks that c + a ≡ 0 for all coefficients; it is the masked equality test of the KeyGen duplicate check (B.8).
- **Hiding:** PWM / ADD / SUB / MSPLIT run their 128 words in a fresh uniformly random order (Fisher–Yates, `pqse_perm.v`, 2 clocks per element). Every NTT / INTT layer gets its own order, drawn in the background while the previous layer runs. Before every engine start the sequencer inserts 0–15 random dummy clocks.

## B.6 Masked gadgets (`pqse_masked.v`, `pqse_mcomp.v`)

- **Masked CBD (B2A).** The PRF output arrives as Boolean shares. Each bit b = b₀ ⊕ b₁ with weight v becomes arithmetic shares using one fresh R mod q: T = v·b₀ − R (registered), then A₀ = b₁ ? −T : T and A₁ = b₁ ? v − R : R. The sum A₀ + A₁ = v·(b₀ ⊕ b₁). The CBD weights per coefficient are +1, +1, −1, −1.
- **Masked Compress_d** (d = 1, 4, 10):
  - each share is scaled on its own, y_s = round(x_s · 2^K / q) mod 2^K with K = d + 14;
  - then a bit-serial ripple-carry adder on Boolean sharings, with DOM AND carries and compress registers, two clocks per bit;
  - the top d bits of the sum are Compress_d(x).

  It has three output modes:
  - m′ as Boolean shares;
  - each bit compared with the public ciphertext bit and ANDed into a masked `ok`;
  - the ciphertext bit unmasked from two dedicated registers (Encaps output).
- **FO comparison.** Two independently masked `ok` accumulators. OKCHK compares them (fault check) through per-domain registered differences, and the implicit-rejection select K = ok ? K′ : K̄ is a DOM AND per bit.
- **Robust-probing rules enforced by construction** (and checked by `pqse_probe_verify.py`):
  - shares meet only in registered DOM cross terms;
  - every DOM result passes a compress register before reuse;
  - unmasking happens only from two registers no other path loads;
  - RAM words follow the order share 0 → public → share 1.

## B.7 Entropy, PUF and persistent state

- **TRNG** (`pqse_rng.v`): ring oscillators folded into a bit stream, with the SP 800-90B repetition-count and adaptive-proportion tests and a start-up test. Raw words are conditioned by masked SHA3-256 before use as seeds. A failure gives result 5, but ZEROIZE still runs.
- **PRNG** (Trivium, 32 rounds per clock): delivers 64-bit mask words and is reseeded from the TRNG at the start of every command. A hardware check raises FAULT if a word is used before it is entirely fresh, which would mean reused masks.
- **PUF** (`pqse_puf.v`): 960 cells, each the cross-coupled storage core of an SRAM cell, read by "re-powering" one row of 32. The fuzzy extractor is a code-offset construction with 30 blocks of RM(1,5), correcting up to 7 errors per 32 bits. Decoding is maximum-likelihood on masked data. A 64-bit check value H(k‖"C") is stored in the helper data. If it doesn't match, the key is re-read with a 3-read and then a 5-read majority vote. KEK = SHA3-256(k ‖ "K"). The blob is a nonce, d‖z ⊕ SHAKE256(KEK‖nonce), and a SHA3-256 tag.
- **Persistent store** (`pqse_nvm` in `pqse_host.v`): set-only thermometer bits, stored twice and OR-combined, holding the lifecycle, the 1st–3rd fault and tampered. After a fault, kill or tamper event the host accepts no command until the store is programmed (write-ahead). A store "ahead" of the registers (rollback) is treated as tampering. On a chip this module is the wrapper of an OTP / eFuse macro with the same ports.

## B.8 Fault detection

| Detector | Covers |
|---|---|
| pc + complemented shadow; sequencer state + shadow; instruction parity; engine-ran check | skipped / repeated instructions, a sequencer stopped mid-command, suppressed engine starts |
| Complemented shadows of the Keccak pass, round, column, plane and lane counters and the sponge state | skipped rounds (a weakened hash that parity can't see), jumps between sponge states |
| Parity on every polynomial, seed and Keccak RAM word and on the θ column parities | bit flips in stored keys and intermediates |
| Two masked `ok` copies + OKCHK; m′ decoded twice with fresh masks and compared share-wise | the classic FO-bypass faults in Decaps (forcing "c′ = c", disturbing the decoder) |
| PRNG freshness check | reused mask bits |
| Host watchdog (2²² clocks) | any hang; kept in the host because a stopped core also stops its own cycle counter |
| **KeyGen duplicate computation:** G(d‖3) and every secret polynomial (PRF → masked CBD → NTT) computed twice with fresh masks, then compared share-wise (SUB per share, then ZCHK) | faults that change ek and dk *consistently*: a coefficient off by a few, a polynomial forced to zero (weak key), two secret polynomials made equal (PRF nonce faults) |
| **KeyGen pairwise consistency test** (FIPS 140-3): masked Encaps to the new ek, Decaps with the new key, K compared | faults that make ek and dk disagree (t̂, ŝ, H(ek)); after the duplicate check every single fault in KeyGen key material is detectable |
| Complemented shadows of lifecycle, fault counter, tampered + persistent store | flipped or rolled-back security state |

**Response:**
1. The command ends with result FAULT.
2. The host resets every engine.
3. ZEROIZE wipes all RAMs, seeds and the buffer windows.
4. The fault is counted and written to the persistent store before any further command.
5. The third fault moves the lifecycle to KILLED.

A tamper input, or a corrupted security state, goes to KILLED immediately.

## B.9 Interface

- **Registers:** ID, VERSION, CTRL (command), STATUS (busy, done, key loaded, TRNG state, tampered, lifecycle, result, session key, fault count), CYCLES, LIFECYCLE, CONFIG (hiding on / off).
- **Buffer:** a 4 KB buffer, accessible only while no command runs, through fixed windows whose read / write rights depend on the lifecycle. In the USER state, K is never readable.
- **SPI:** `02 aH aL` + data (write), `03 aH aL xx` + data (read), 4 bytes per word, LSB first.

The full maps are in `hw/se/README.md`, section 10.

## B.10 Measured results

**Performance** (Verilator, hiding on):

| Command | Clocks | 3.39 MHz | 50 MHz |
|---|---|---|---|
| KeyGen (incl. duplicate check and pairwise test) | 545,344 | 161 ms | 10.9 ms |
| Encaps | 267,964 | 79 ms | 5.4 ms |
| Decaps | 298,465–304,526 | 88–90 ms | 6.0–6.1 ms |
| UNWRAP (key restored from the blob) | 271,738 | 80 ms | 5.4 ms |
| SEAL / OPEN, 128 B | 22,550 | 6.7 ms | 0.45 ms |

**Gate level, SkyWater 130 nm** (sky130_fd_sc_hd, tt / 25 °C / 1.8 V; Yosys mapping with automatic clock gating, OpenSTA with the switching activity of a whole simulated KeyGen; SRAMs as macros, energy from access counts with an assumed energy per access; no clock tree or wires):

| KeyGen | |
|---|---|
| Energy | 73.5 µJ (logic 52.0, SRAM 21.5) |
| Energy per clock | 133.8 pJ |
| Average power at 3.39 MHz | 0.45 mW |
| Flip-flops / behind clock gates | 7,775 / 7,526 (285 integrated clock gates) |
| Worst setup slack at 20 ns | 7.2 ns (≈ 78 MHz logic-only, ideal clock) |

Giving the last ~900 every-cycle flip-flops plain enables (θ column parities, χ operands, CSR, counters) took KeyGen from 92.5 to 73.5 µJ. The SRAMs are now 29 % of the energy; their energy per access is an assumption.

**FPGA** (an earlier v4 build, before the fault hardening; Gowin EDA place and route, GW2AR-18 / Tang Nano 20K): 15,881 logic units (77 %), 8,779 registers (56 %, including 1,920 PUF latches), 15 of 46 block RAMs, 14.75 of 24 DSP. It fits, but at 94 % of the logic cells.

**Security checks:**

| Check | Result |
|---|---|
| NIST ACVP known answers (KeyGen, Encaps), masked Decaps incl. implicit rejection, all functional and fault / tamper tests (`make sim-se`, also with operand isolation) | pass |
| Exhaustive first-order robust-probing check, glitches and transitions, every gadget, with negative controls (`make se-probe`) | pass |
| TVLA, fixed-vs-random, two independent runs (`pqse_tvla.py confirm`) | no confirmed first-order leakage |
| Fault campaign: 200 random single-bit flips per command, 38 targets, every run a cold chip | Decaps: 111 unchanged, 74 detected, 15 implicit rejection, **0 silent**, 0 hang; KeyGen: 127 unchanged, 73 detected, **0 silent**, 0 hang |

## B.11 Low-power design

- One engine at a time. Every pipeline register has an enable, and registers are cleared once when going idle and then held, so they can be clock-gated.
- Registers are written only in the clocks where their value changes. For example, the χ operands and products are written in 2 of the 4 clocks of a lane slot, and each θ column-parity lane only on a write-back of that column.
- Operand isolation (`PQSE_LOWPOWER`): shared buses and the PRNG word reach an engine only while it is busy.
- Automatic clock gating in synthesis: integrated clock-gate cells, groups of ≥ 4 flip-flops per enable. Registers with a synchronous reset over the enable are rewritten so they can be gated.
- RAM read enables only in clocks that need the data, and one RAM per share, so the share-1 RAMs idle in unmasked jobs.
- `make se-power` lists every flip-flop still clocked every cycle, by RTL register.

## B.12 Implementation notes (ASIC)

- **Macros needed:** single-port-read / single-port-write SRAMs (2 × 1024 × 25, 2 × 64 × 65 Keccak, 2 × 512 × 32), possibly a ROM for the microcode, OTP / eFuse for the persistent store. The PUF cells and the TRNG ring oscillators are full-custom or characterized analog cells. Tamper sensors (glitch, temperature, light, shield) OR into the tamper input.
- **Single clock domain.** SPI and tamper inputs are synchronized. Reset is asserted asynchronously and released synchronously.
- **Masking caveat.** Synthesis must not merge the two shares' logic. Keep the gadget modules as hierarchy, or verify the netlist with a netlist-level probing tool (e.g. PROLEAD). The register-level checks here don't see netlist effects or coupling inside SRAM macros.
- **Test:** no scan chain is inserted in the RTL. On a product, scan would be gated by the lifecycle, like the other debug features.

## B.13 Verification flow

1. `make sim-se`: Python models of the gadget math, the probing check, then the RTL testbench (NIST vectors, all commands, lifecycle, persistence, injected faults, SPI). It also runs an independent KMAC check of the sealed messages and PUF / TRNG statistics.
2. `make se-probe`: robust-probing check of the gadgets, alone.
3. `make sim-se-tvla` twice (two seeds), then `pqse_tvla.py confirm`. `MASKED=0` is the positive control and must leak.
4. `make sim-se-fault FN=200` (Decaps and `FOP=keygen`): random fault injection with null control and outcome classes.
5. `make se-power`, `make se-power-vcd` (sky130, needs OpenSTA and the liberty file); `make se-gowin` / `se-gowin-eda` (Tang Nano 20K); `quartus_sh -t build.tcl se` (DE10-Nano).

## B.14 Limits and possible extensions

- **Masking order.** First-order masking plus hiding is the usual trade-off for smart-card-class area and power. Higher order would cost about 3–4× in area and time.
- **FPGA PUF and TRNG.** On an FPGA they demonstrate the interfaces and the post-processing; routing makes FPGA PUF cells more biased than silicon ones.
- **Extension:** ML-DSA (FIPS 204) signatures on the same Keccak and polynomial datapath.

## Glossary

| Term | Meaning |
|---|---|
| ML-KEM | Module-Lattice-based Key-Encapsulation Mechanism, FIPS 203 (Kyber) |
| ek / dk / K | encapsulation (public) key / decapsulation (secret) key / shared secret |
| NTT | number-theoretic transform, the fast polynomial multiplication method of ML-KEM |
| Keccak / SHA-3 / SHAKE | the hash function family ML-KEM uses for its random-looking values |
| Masking, share | splitting a secret x into random parts (x₀, x₁) with x = x₀ ⊕ x₁ (Boolean) or x₀ + x₁ mod q (arithmetic) |
| DOM | domain-oriented masking: an AND gate on shares, with fresh randomness and registers between the share domains |
| Robust probing model | a security model in which an attacker probe also sees glitches (combinational paths up to the next register) and transitions (consecutive register values) |
| TVLA | test vector leakage assessment: a Welch t-test between power traces of fixed and random inputs; \|t\| > 4.5 marks leakage |
| FO transform / implicit rejection | the re-encryption check in Decaps; an invalid ciphertext yields a pseudo-random key instead of an error |
| PUF | physically unclonable function: a chip fingerprint from manufacturing variation |
| Fuzzy extractor | error correction that turns a noisy PUF response into a stable key, using public helper data |
| Clock gating | switching off the clock of registers that don't change, to save power |
