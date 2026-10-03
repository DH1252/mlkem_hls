# PQSE design document

Part A explains what the chip is for and how it protects its secrets, without assuming a background in hardware or cryptography. Part B is the engineering description for VLSI and security engineers: architecture, memories, countermeasures, verification and measured results. Terms are explained where they first appear and again in the glossary at the end.

The source is in `hw/se/`. Register maps, the microcode map, testbench details and debugging notes are in [`hw/se/README.md`](../hw/se/README.md).

---

# Part A: in plain language

## A.1 The problem

When a phone, an ID card or a payment terminal opens a secure connection, the two sides first agree on a secret key that an eavesdropper can't learn. Today that agreement uses RSA or elliptic curves, and a large quantum computer would break both. Traffic recorded now could be decrypted once such a computer exists. In 2024 the US standards body NIST published a replacement that no known quantum algorithm breaks: ML-KEM (FIPS 203), formerly called Kyber.

ML-KEM is heavier than what it replaces. Its keys are 1 to 2 KB instead of 32 to 64 bytes, and it needs hundreds of thousands of arithmetic steps. A contactless card has no battery and runs on a few milliwatts drawn from the reader's radio field, so running ML-KEM in software on such a card is slow. Software also leaks its secrets through the chip's power consumption.

## A.2 What a secure element is

A secure element is the small, hardened chip inside a bank card, an e-passport or a SIM. It keeps keys that never leave it, does the cryptography itself, and is built to resist an attacker who holds the chip. That attacker can measure its power consumption or electromagnetic emission while it computes and use statistics to recover the key (a side-channel attack). They can disturb it with a voltage glitch, a clock glitch or a laser pulse so that it makes a mistake that reveals the key (a fault attack). And they can try every command and debug feature on its interface.

PQSE is a secure element for ML-KEM-768. It exists as a hardware description in Verilog, which runs on an FPGA (a reprogrammable chip) today and is meant to be manufactured as a chip.

## A.3 What it does

It performs the three ML-KEM operations: making a key pair (KeyGen), creating a shared secret for someone else's public key (Encaps), and recovering a shared secret sent to its own public key (Decaps).

It keeps the shared secret inside as a session key and uses it to encrypt and authenticate messages (SEAL and OPEN), so the secret never has to leave the chip.

It stores its long-term key without non-volatile memory. The key is encrypted under a key that the chip derives from its own physical fingerprint, a PUF (physically unclonable function). Tiny random differences from manufacturing make every chip's PUF output unique, so the stored data is useless on another chip.

It has a lifecycle. In the TEST state it is open for manufacturing tests; in PERSO (personalization) keys are loaded; in USER it is in the field and locked; KILLED means permanently disabled. It can only move forward through these states.

## A.4 How it protects its secrets

| Attack | Defence |
|---|---|
| Measuring power or EM emission | Masking. Every secret is split into two random parts that are processed separately. Each part alone is pure noise, and the chip never puts the parts back together. |
| The same, averaged over many measurements | Hiding. The order of operations is shuffled at random each time and random pauses are inserted, so measurements don't line up. |
| Timing | Every operation takes the same time whatever the secret. |
| Glitches and lasers | Self-checks. Important values are computed twice and compared, control registers have inverted twins, every memory word carries a check bit, and a new key is test-used before release. On any mismatch the chip wipes its keys; after three such events it disables itself for good. |
| Opening the package | A tamper input wipes everything and kills the chip. |
| Stealing the stored key | The stored key is encrypted under the chip's own fingerprint. |
| Abusing debug features | Debug and test functions work only in the TEST state, and the lifecycle can't go back. |

## A.5 How we know it works

- It reproduces NIST's official test vectors for ML-KEM.
- A standard leakage test (TVLA) on simulated power traces finds no first-order leakage, and every masked circuit passes a mathematical check that includes glitches.
- In 400 simulated fault injections, each flipping one random bit somewhere in the chip at a random moment, the chip never gave a wrong answer without noticing. Some faults ended in the designed safe outcome: a random-looking key instead of an error.
- One key generation takes about 0.16 s at the 3.39 MHz clock a contactless reader provides, and about 73.5 µJ of energy, an average of 0.45 mW. A reader's field can supply that.

---

# Part B: engineering description

## B.1 Specification

| Item | Value |
|---|---|
| Algorithms | ML-KEM-768 (FIPS 203) KeyGen, Encaps, Decaps with implicit rejection; SHA3-256/512, SHAKE128/256 (FIPS 202); KMAC256 (SP 800-185) |
| Object sizes | ek 1,184 bytes; dk 2,400 bytes, held inside as masked ŝ, H(ek) and z; ciphertext 1,088 bytes; shared secret 32 bytes |
| Commands | KEYGEN, ENCAPS, DECAPS, IMPORT, ENROLL, KGWRAP, UNWRAP, ZEROIZE, SEAL, OPEN, PUFRAW, TRNGRAW |
| Host interface | 32-bit register bus (registers and a 4 KB I/O buffer), read latency 1; SPI slave mode 0 on the chip, Avalon-MM on the FPGA |
| Pins (chip) | clk, rst_n, SPI (4), IRQ, tamper in, trigger out (TEST state only) |
| Clock | one clock domain; 50 MHz on the FPGA, 3.39 MHz (13.56 MHz / 4) in a contactless card |
| Reset | asserted asynchronously, released synchronously in `pqse_top`; synchronous inside |
| Side-channel protection | first-order Boolean and arithmetic masking of every secret with DOM gadgets, checked in the robust probing model; shuffling and dummy cycles; constant time |
| Fault protection | duplicated computation with comparison, complemented shadow registers, parity, control-flow checks, watchdog, PRNG freshness check, KeyGen pairwise consistency test; wipe and count on detection, KILLED after 3 faults |
| Randomness | ring-oscillator TRNG with SP 800-90B health tests and SHA3-256 conditioning; Trivium PRNG for masks, reseeded per command |
| Key storage | PUF of 960 SRAM-type cells, RM(1,5) code-offset fuzzy extractor with masked decoding, key-encryption key, wrapped-key blob |
| Persistent state | lifecycle, fault counter and tamper flag in a set-only store (OTP or eFuse semantics) |

## B.2 Architecture

```
                 SPI / Avalon-MM            tamper   IRQ   trigger
                       |                       |      ^      ^
   +-------------------v-----------------------v------+------+------+
   | pqse_host                                                      |
   |  registers, lifecycle FSM (+ complemented shadows), buffer     |
   |  windows, command policy, K-export policy, fault counter,      |
   |  watchdog, persistent store (pqse_nvm), wipe on power-on,      |
   |  fault and tamper                                              |
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

**Execution model.** A microcoded sequencer runs one instruction at a time: fetch, an optional shuffle-order draw, optional dummy clocks, start the engine, wait until it reports done. Only one engine is ever active. Every RAM port is therefore a plain multiplexer selected by the instruction class with no arbitration or hazard logic, idle engines hold still, and only one operation contributes to the power trace at a time. The design trades speed for area and energy because a contactless card runs at 3.39 MHz and the reader grants waiting-time extensions.

**Instructions.** A 96-bit instruction has one of eight classes: END, BR (branch on a flag), SET (status flags, reseed), HASH (a complete sponge job with its sources, padding, rate, masking and sink), POLY, IO, MASK and PUF. One ML-KEM operation is a few hundred instructions. Programs sit at fixed ROM addresses, for example KeyGen at 16 and 80, Encaps at 192, Decaps at 320, the pairwise test at 608 and the KeyGen duplicate checks at 720.

## B.3 Data representation and memories

| Memory | Organization | Contents | FPGA / ASIC |
|---|---|---|---|
| Polynomial RAM 0 and 1 | 1024 x 25 each: two 12-bit coefficients plus parity per word, 16 slots of 128 words | even slots in RAM 0 (share 0 and public data), odd slots in RAM 1 (share 1) | M10K / SRAM macro |
| Seed RAM 0 and 1 | 64 x 65 each: a 64-bit lane plus parity, 16 entries of 4 lanes | Boolean shares of seeds and keys: d, z, m, K, ρ, σ, the session key, the KEK | MLAB / register file or SRAM |
| Keccak state RAM 0 and 1 | 64 x 65 each | one share of the 25 state lanes and of the ρπ output, with parity | M10K / SRAM macro |
| I/O buffer | 2 x 512 x 32 (4 KB) | ek, ciphertexts, PUF helper data, wrapped key, messages | M10K / SRAM macro |
| Microcode ROM | 1024 x 96, registered read | the programs | M10K ROM / ROM or logic |
| Shuffle table | 128 x 7, two reads and one write | Fisher–Yates permutation | MLAB / register file |

**Share separation.** The two shares of a secret always sit in different RAMs: share 0 in RAM 0, share 1 in RAM 1, for polynomials, seeds and the Keccak state. A RAM's read register, bus or output multiplexer never holds both shares of one value. Between instructions the sequencer precharges both polynomial-RAM output registers: during fetch it reads an all-zero slot from RAM 1 and a public word from RAM 0, so an instruction's first read never follows the other share of the same coefficient.

## B.4 Masked Keccak (`pqse_keccak.v`, `pqse_sponge.v`)

Keccak-f[1600] is the permutation inside SHA-3 and SHAKE. ML-KEM uses it for every hash, for its pseudorandom function (PRF) and for expanding seeds into matrices.

- **Datapath.** One 64-bit lane per clock, with the state in RAM (one RAM per share, one read and one write per clock). A round has a θ+ρ+π pass (RP, 26 clocks) and a χ+ι pass (CHI, 100 clocks). The θ column parities are kept in registers and updated by the χ write-back, so only round 0 needs a separate θ parity pass (26 clocks). That gives 126 clocks per round and about 3,050 per permutation.
- **Masked χ.** χ is the only nonlinear step. Per lane the RTL loads X = ¬a[x+1] and Y = a[x+2] one lane each, computes one DOM AND with 64 fresh random bits, then writes back. X and Y hold their values only in their slot clocks and are cleared after the AND, so the AND never sees both shares of a lane, not even in consecutive clocks. `make se-probe` checks this schedule, together with a variant that holds the operands, which must fail.
- **Fault detection.** A parity bit on every state word and on each column-parity register, checked on use per share. The pass, round, column, plane and lane counters have complemented shadows written in the same statements; any mismatch raises a fault.
- **Sponge.** Sources are seed entries (masked), buffer lanes (public) and TRNG words. Rates are 168, 136 and 72 bytes with SHA-3, SHAKE and cSHAKE padding and KMAC framing. Sinks write or XOR into seed entries, or feed SampleNTT, the masked CBD, the masked compare or the message keystream. A masked job feeds public data into share 0 only.

## B.5 Polynomial unit (`pqse_poly.v`, `pqse_arith.v`, `pqse_perm.v`)

ML-KEM multiplies polynomials with the number-theoretic transform (NTT), a fast Fourier transform over integers mod q = 3329.

- **Datapath.** One 12 x 12 modular multiplier (Barrett reduction with 5039 = ⌊2²⁴/q⌋, 4-stage pipeline) and one butterfly. NTT and INTT run one butterfly per clock over 7 layers, about 970 clocks per transform. Pointwise multiplication (PWM, the base-case products of FIPS 203 Algorithms 11 and 12) takes one coefficient pair per 6 clocks, about 780 clocks. ADD and SUB take one word per 2 clocks.
- **Per share.** NTT, INTT and PWM are linear, so they run on each share separately. Only the public t̂ is ever recombined.
- **Other operations.** MSPLIT splits an imported key into two arithmetic shares. ZCHK raises FAULT unless two polynomials sum to 0 mod q in every coefficient; it is the masked equality test of the KeyGen duplicate check (B.8).
- **Hiding.** PWM, ADD, SUB and MSPLIT process their 128 words in a fresh uniformly random order (inside-out Fisher–Yates, `pqse_perm.v`, 2 clocks per element). Every NTT and INTT layer gets its own order, drawn in the background while the previous layer runs. Before every engine start the sequencer inserts 0 to 15 random dummy clocks.

## B.6 Masked gadgets (`pqse_masked.v`, `pqse_mcomp.v`)

A gadget is a small circuit that computes on shares. Linear steps work share by share; the gadgets below handle the nonlinear steps and the conversions between Boolean shares (x = x₀ ⊕ x₁) and arithmetic shares (x = x₀ + x₁ mod q).

- **Masked CBD (B2A).** ML-KEM samples its small secret and error polynomials from a centered binomial distribution (CBD) of PRF output bits. The PRF output arrives as Boolean shares. Each bit b = b₀ ⊕ b₁ with weight v becomes arithmetic shares using one fresh R mod q: T = v·b₀ − R (registered), then A₀ = b₁ ? −T : T and A₁ = b₁ ? v − R : R, so A₀ + A₁ = v·b. The CBD weights per coefficient are +1, +1, −1, −1.
- **Masked Compress_d** (d = 1, 4, 10). Compress rounds a coefficient to d bits. Each share is scaled on its own, y_s = round(x_s · 2^K / q) mod 2^K with K = d + 14. A bit-serial ripple-carry adder then adds the two scaled shares on Boolean sharings, with DOM AND carries and compress registers, two clocks per bit. The top d bits of the sum are Compress_d(x). There are three output modes: m′ as Boolean shares (Decaps decoding); each bit compared with the public ciphertext bit and ANDed into a masked `ok` (the re-encryption check); and the ciphertext bit unmasked from two dedicated registers (Encaps output).
- **FO comparison.** Decaps re-encrypts the decoded message and checks that the result equals the received ciphertext (the Fujisaki–Okamoto, or FO, transform). Two independently masked `ok` accumulators collect the comparison. OKCHK compares them through per-domain registered differences as a fault check. The implicit-rejection select K = ok ? K′ : K̄ is a DOM AND per bit, so an invalid ciphertext yields a pseudorandom key and the comparison result is never unmasked.
- **Rules.** Shares meet only in registered DOM cross terms; every DOM result passes a compress register before reuse; unmasking happens only from two registers that no other path loads; RAM words are read in the order share 0, public, share 1. `scripts/pqse_probe_verify.py` checks all of these.

## B.7 Randomness, PUF and persistent state

- **TRNG** (`pqse_rng.v`). Ring oscillators produce a raw bit stream, monitored by the SP 800-90B repetition-count, adaptive-proportion and start-up tests. Raw words are conditioned by masked SHA3-256 before use as seeds. A failure gives result 5; ZEROIZE still runs.
- **PRNG** (Trivium, 32 rounds per clock). Delivers 64-bit mask words and is reseeded from the TRNG at the start of every command. A hardware check raises FAULT if a word is used before it is entirely fresh, since that would reuse mask bits.
- **PUF** (`pqse_puf.v`). 960 cells, each the cross-coupled storage core of an SRAM cell, read by re-powering one row of 32 so each read repeats the power-up race. The fuzzy extractor, which turns the noisy response into a stable key using public helper data, is a code-offset construction over 30 blocks of the Reed–Muller code RM(1,5), correcting up to 7 errors per 32 bits. Decoding is maximum-likelihood on masked data. A 64-bit check value H(k‖"C") in the helper data tells whether reconstruction worked; if it didn't, the key is re-read with a 3-read and then a 5-read majority vote. The key-encryption key is KEK = SHA3-256(k ‖ "K"), and the stored blob is a nonce, d‖z ⊕ SHAKE256(KEK‖nonce), and a SHA3-256 tag.
- **Persistent store** (`pqse_nvm` in `pqse_host.v`). Set-only thermometer bits, stored twice and OR-combined, hold the lifecycle, the first to third fault and the tamper flag. After a fault, kill or tamper event the host accepts no command until the store is programmed. A store that is ahead of the registers (a rollback) is treated as tampering. On a chip this module wraps an OTP or eFuse macro with the same ports.

## B.8 Fault detection

| Detector | Covers |
|---|---|
| pc with a complemented shadow; sequencer state with a shadow; instruction parity; engine-ran check | skipped or repeated instructions, a sequencer stopped mid-command, suppressed engine starts |
| Complemented shadows of the Keccak pass, round, column, plane and lane counters and of the sponge state | skipped rounds (a weakened hash that parity can't see), jumps between sponge states |
| Parity on every polynomial, seed and Keccak RAM word and on the θ column parities | bit flips in stored keys and intermediates |
| Two masked `ok` copies with OKCHK; m′ decoded twice with fresh masks and compared share-wise | the classic FO-bypass faults in Decaps: forcing "c′ = c", disturbing the decoder |
| PRNG freshness check | reused mask bits |
| Host watchdog (2²² clocks) | any hang; it sits in the host because a stopped core also stops its own cycle counter |
| KeyGen duplicate computation: G(d‖3) and every secret polynomial (PRF, masked CBD, NTT) computed twice with fresh masks, then compared share-wise (SUB per share, then ZCHK) | faults that change ek and dk consistently: a coefficient off by a few, a polynomial forced to zero (a weak key), two secret polynomials made equal by a PRF nonce fault |
| KeyGen pairwise consistency test (FIPS 140-3): masked Encaps to the new ek, Decaps with the new key, K compared | faults that make ek and dk disagree (t̂, ŝ, H(ek)) |
| Complemented shadows of lifecycle, fault counter and tamper flag; persistent store | flipped or rolled-back security state |

The duplicate computation and the pairwise test complement each other. A fault before the comparison point changes both keys consistently and is caught by the duplicate; a fault after it, in t̂ or the stored ŝ, makes the key pair inconsistent and is caught by the pairwise test.

On detection the command ends with result FAULT, the host resets every engine, ZEROIZE wipes all RAMs, seeds and buffer windows, and the fault is counted and written to the persistent store before any further command. The third fault moves the lifecycle to KILLED. The tamper input, or a corrupted security state, goes to KILLED at once.

## B.9 Interface

- **Registers.** ID, VERSION, CTRL (command), STATUS (busy, done, key loaded, TRNG state, tampered, lifecycle, result, session key, fault count), CYCLES, LIFECYCLE, CONFIG (hiding on or off).
- **Buffer.** 4 KB, accessible only while no command runs, through fixed windows whose read and write rights depend on the lifecycle. K is never readable in USER.
- **SPI.** Write `02 aH aL` then data, read `03 aH aL xx` then data; 4 bytes per word, least significant byte first.

The full maps are in `hw/se/README.md`, section 10.

## B.10 Measured results

**Speed** (Verilator, hiding on):

| Command | Clocks | at 3.39 MHz | at 50 MHz |
|---|---|---|---|
| KeyGen, with duplicate check and pairwise test | 545,344 | 161 ms | 10.9 ms |
| Encaps | 267,964 | 79 ms | 5.4 ms |
| Decaps | 298,465 to 304,526 | 88 to 90 ms | 6.0 to 6.1 ms |
| UNWRAP (key restored from the blob) | 271,738 | 80 ms | 5.4 ms |
| SEAL or OPEN, 128 bytes | 22,550 | 6.7 ms | 0.45 ms |

**Gate level, SkyWater 130 nm.** Cells from sky130_fd_sc_hd at typical corner, 25 °C, 1.8 V. Yosys maps the design with automatic clock gating; Verilator simulates a whole KeyGen on the netlist; OpenSTA computes power from the recorded switching activity (a SAIF file). SRAMs are macros whose energy is the access count times an assumed energy per access. Clock tree and wires are not included.

| KeyGen | |
|---|---|
| Energy | 73.5 µJ (logic 52.0, SRAM 21.5) |
| Energy per clock | 133.8 pJ |
| Average power at 3.39 MHz | 0.45 mW |
| Flip-flops | 7,775, of which 7,526 behind 285 integrated clock gates |
| Worst setup slack at 20 ns | 7.2 ns (about 78 MHz for the logic alone, ideal clock) |

Adding plain enables to the last ~900 flip-flops that were clocked every cycle (θ column parities, χ operands, the host's register-read latch, counters) took KeyGen from 92.5 to 73.5 µJ. The SRAMs are now 29 % of the energy, and their energy per access is still an assumption; `make se-sram-char` replaces it with OpenRAM SPICE characterization.

**FPGA.** An earlier v4 build, before the fault hardening, on the Gowin GW2AR-18 (Tang Nano 20K) with Gowin EDA place and route: 15,881 logic units (77 %), 8,779 registers (56 %, including 1,920 PUF latches), 15 of 46 block RAMs, 14.75 of 24 DSP blocks. It fits, at 94 % of the logic cells.

**Security checks:**

| Check | Result |
|---|---|
| NIST ACVP known answers (KeyGen, Encaps), masked Decaps with implicit rejection, all functional, fault and tamper tests (`make sim-se`, also with operand isolation) | pass |
| Exhaustive first-order robust-probing check with glitches and transitions, every gadget, with negative controls (`make se-probe`) | pass |
| TVLA, fixed versus random, two independent runs (`pqse_tvla.py confirm`) | no confirmed first-order leakage |
| Fault campaign: 200 random single-bit flips per command, 38 targets, each run a freshly powered chip | Decaps: 111 unchanged, 74 detected, 15 implicit rejection, 0 silent, 0 hang. KeyGen: 127 unchanged, 73 detected, 0 silent, 0 hang. |

## B.11 Low-power design

- One engine runs at a time. Pipeline registers have enables, and registers are cleared once when going idle and then held, so they can be clock-gated.
- Registers are written only in clocks where their value changes. The χ operands and products, for example, are written in 2 of the 4 clocks of a lane slot, and each θ column-parity lane only on a write-back of that column.
- Operand isolation (`PQSE_LOWPOWER`): shared buses and the PRNG word reach an engine only while it is busy.
- Synthesis inserts integrated clock-gate cells for groups of 4 or more flip-flops on one enable. Registers with a synchronous reset over the enable are rewritten first so they can be gated.
- RAM read enables are active only in clocks that use the data, and with one RAM per share the share-1 RAMs stay idle in unmasked jobs.
- `make se-power` lists every flip-flop still clocked every cycle, by RTL register.

## B.12 Implementation notes for an ASIC

- **Macros.** One-read, one-write SRAMs (2 x 1024 x 25, 2 x 64 x 65 for Keccak, 2 x 64 x 65 for seeds, 2 x 512 x 32), possibly a ROM for the microcode, and OTP or eFuse for the persistent store. The PUF cells and the TRNG ring oscillators are full-custom or characterized analog cells. Tamper sensors (glitch, temperature, light, shield) OR into the tamper input.
- **Clocking and reset.** One clock domain. SPI and tamper inputs are synchronized. Reset is asserted asynchronously and released synchronously.
- **Masking and synthesis.** Synthesis must not merge logic of the two shares. Keep the gadget modules as separate hierarchy, or check the netlist with a netlist-level probing tool such as PROLEAD. The register-level checks here don't see netlist effects or coupling inside SRAM macros.
- **Test.** The RTL has no scan chain. A product would add scan gated by the lifecycle, like the other debug features.

## B.13 Verification flow

1. `make sim-se`: Python models of the gadget arithmetic, the probing check, then the RTL testbench (NIST vectors, all commands, lifecycle, persistence, injected faults, SPI). It also runs an independent KMAC check of the sealed messages and PUF and TRNG statistics.
2. `make se-probe`: the probing check alone.
3. `make sim-se-tvla` with two seeds, then `pqse_tvla.py confirm`. `MASKED=0` is the positive control and must leak.
4. `make sim-se-fault FN=200` for Decaps and `FOP=keygen`: random fault injection sorted into outcome classes.
5. `make se-power` and `make se-power-vcd` (sky130, needs OpenSTA and the Liberty file); `make se-gowin` or `se-gowin-eda` (Tang Nano 20K); `quartus_sh -t build.tcl se` (DE10-Nano).

## B.14 Limits and extensions

- First-order masking plus hiding is the usual trade-off for smart-card area and power. Second-order masking would cost about 3 to 4 times the area and time.
- On an FPGA, the PUF and TRNG demonstrate the interfaces and post-processing; FPGA routing makes PUF cells more biased than on silicon.
- ML-DSA (FIPS 204) signatures could run on the same Keccak and polynomial datapath.

## Glossary

| Term | Meaning |
|---|---|
| ML-KEM | Module-Lattice-based Key-Encapsulation Mechanism, FIPS 203, formerly Kyber |
| ek, dk, K | encapsulation (public) key, decapsulation (secret) key, shared secret |
| KeyGen, Encaps, Decaps | make a key pair; create a shared secret and its ciphertext for a public key; recover the shared secret from a ciphertext |
| Keccak, SHA-3, SHAKE | the hash-function family ML-KEM uses for hashing and for its random-looking values |
| KMAC | a keyed hash built on SHA-3 (SP 800-185), used here to encrypt and authenticate messages |
| NTT, INTT, PWM | number-theoretic transform (fast polynomial multiplication), its inverse, pointwise multiplication |
| CBD | centered binomial distribution, the sampler for ML-KEM's small secret polynomials |
| Compress_d | rounding a coefficient mod q to d bits |
| Masking, share | splitting a secret x into random parts with x = x₀ ⊕ x₁ (Boolean) or x = x₀ + x₁ mod q (arithmetic) |
| B2A | conversion from Boolean to arithmetic shares |
| DOM | domain-oriented masking: an AND gate on shares, with fresh randomness and registers between the share domains |
| Gadget | a small masked circuit, such as a masked AND or a masked adder |
| Robust probing model | a security model in which a probe on a wire also sees glitches (everything up to the previous registers) and transitions (consecutive values of a register) |
| TVLA | test vector leakage assessment: a Welch t-test between power traces of fixed and random inputs; \|t\| > 4.5 marks leakage |
| Hiding | making leakage harder to align: random operation order, random dummy cycles |
| FO transform, implicit rejection | the re-encryption check in Decaps; an invalid ciphertext yields a pseudorandom key instead of an error |
| Pairwise consistency test | using a new key pair once (encapsulate, decapsulate, compare) before releasing it, required by FIPS 140-3 |
| Shadow register | a copy of a register holding the inverted value; a mismatch means a fault |
| PUF | physically unclonable function: a chip fingerprint from manufacturing variation |
| Fuzzy extractor | error correction that turns a noisy PUF response into a stable key, using public helper data |
| KEK | key-encryption key, here derived from the PUF |
| TRNG, PRNG | true random number generator (physical noise); pseudorandom generator (Trivium) that stretches TRNG seeds into masks |
| Fisher–Yates | an algorithm that produces a uniformly random permutation |
| OTP, eFuse | one-time-programmable memory on a chip |
| Clock gating | stopping the clock of registers that don't change, to save power; an integrated clock gate (ICG) is the standard cell that does it |
| Operand isolation | holding a block's inputs constant while it is idle so its logic doesn't toggle |
| SAIF | switching activity interchange format: per-net toggle counts used for power analysis |
| M10K, MLAB | block RAM and LUT-based RAM on Intel Cyclone V FPGAs |
