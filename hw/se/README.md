# PQSE RTL reference (`hw/se`)

PQSE is a masked ML-KEM-768 secure element (FIPS 203) for contactless identity and payment cards. This file is the reference for the RTL: the blocks, the interface, the microcode map, where each countermeasure lives, the testbenches and how to debug them. The reasoning behind the design, written for a wider audience, is in [`docs/PQSE_design.md`](../../docs/PQSE_design.md). Section 19 explains the names used in the RTL and in this file.

**Status (v4).** `make sim-se` passes, also with `LOWPOWER=1`. The probing check passes, a two-run TVLA finds no confirmed first-order leakage, and the fault campaign gives no silent fault and no hang for Decaps or KeyGen. Gate-level energy is in section 4. The FPGA board builds have not been run with this version.

## 1. Block diagram

```
            SPI (4 pins) / Avalon-MM (FPGA)      tamper  IRQ   trigger (TEST only)
                       |                            |     ^     ^
              +--------v----------------------------v-----+-----+-----+
              |  pqse_host: registers, lifecycle TEST>PERSO>USER>KILLED|
              |  buffer windows, command and K-export policy,         |
              |  fault counter, watchdog, persistent store, wipes     |
              +----------+----------------------------+---------------+
                         | command, result             | host <-> I/O buffer (idle only)
              +----------v------------+    +----------v---------------------------+
              | sequencer + microcode |    | I/O buffer 4 KB: own ek, PUF helper  |
              | ROM 1024 x 96,        |    | data, peer ek / c in, c out, K       |
              | pc + ~pc shadow,      |    | (TEST/PERSO), wrapped-key blob,      |
              | instruction parity,   |    | secure message                       |
              | engine-ran check,     |    +--------------------------------------+
              | RAM-port precharge    |
              +--+-----+-----+----+---+
                 |     |     |    |      +-------------------+  +----------------------+
   +-------------v-+ +-v-----+-+ +v-----v-+ | seed RAMs         |  | polynomial RAM 0     |
   | masked Keccak | | poly    | | masked  | | 2 x 64 x 65,      |  | even slots: share 0  |
   | state in 2    | | unit:   | | gadgets:| | one per share,    |  | and public, 1024 x 25|
   | RAMs 64 x 65, | | 1 mult, | | CBD/B2A,| | parity            |  +----------------------+
   | DOM chi,      | | 1 BFU,  | | mu, Com-| +-------------------+  | polynomial RAM 1     |
   | sponge, KMAC, | | shuffled| | press,  |                        | odd slots: share 1   |
   | SampleNTT     | |         | | compare,| +-------------------+  |            1024 x 25 |
   +-------+-------+ +----+----+ | select, | | I/O unit: encode, |  +----------------------+
           |              |      | 2 x ok  | | decode, seed ops, |  | PUF: 960 SRAM-type   |
   +-------v--------------+--+   +---------+ | counters, SEQ     |  | cells, RM(1,5) fuzzy |
   | TRNG (ring osc. + SP    |               +-------------------+  | extractor, masked    |
   | 800-90B tests), Trivium |  Fisher-Yates shuffler,              | decoding, retries    |
   | PRNG, 64 bits per clock |  128 x 7 2R1W register file          +----------------------+
   +-------------------------+  (pqse_perm.v)
```

## 2. Design choices

| Choice | Effect |
|---|---|
| One engine at a time under microcode; each RAM port is a multiplexer selected by the instruction class | No hazard logic or extra RAM ports. Idle engines don't toggle, peak current stays low, and only one operation shows in the power trace. |
| One modular multiplier and one butterfly for NTT, INTT and PWM; 1R1W RAMs with two coefficients per word | The earlier fast core (v2) had 7 to 14 multipliers. |
| Lane-serial Keccak with the state in two RAMs (one per share), 64-bit datapath | The 3,200 state bits leave the flip-flops (v3 used about 5,100 flip-flops for Keccak) and the 25-way lane multiplexers go away. 126 clocks per round. |
| Microcode in a ROM with a registered read (two-clock fetch) | A ROM block instead of about 100 k gates of decode logic. |
| Masking linear steps by running them once per share | NTT, INTT and PWM cost time per share and no extra area. |
| Bit-serial masked gadgets (CBD/B2A, Compress, compare, select) | One DOM AND gate per gadget. |
| Shares in separate RAMs (polynomial slots, seeds, Keccak state) | The two shares never share a bit line, sense amplifier or output register. Cost: one parity bit per word, which also serves fault detection. |
| Shuffle table in a 128 x 7 register file (2 reads, 1 write) | About 1 k fewer flip-flops than a flip-flop table. LUTRAM / MLAB on an FPGA. |
| Parity and control-flow shadows everywhere; duplicated computation only where a fault would leak or give a bad key | One parity bit per RAM word, a 10-bit pc shadow, one parity bit per instruction. |
| SRAM-type PUF cells (960 cross-coupled NAND pairs, read one row of 32 at a time) | 2 gates per bit instead of the 1,920 ring oscillators of v3. Only the row being read switches. |
| `MASKED = 0` build | Removes the share-1 seed RAM and the masked Keccak; masks are 0. Used for cost comparison and as the TVLA positive control. |

## 3. Speed

Measured with `make sim-se LOWPOWER=1`, hiding on. A Keccak permutation takes about 3,050 clocks and a KEM operation needs about 50 of them.

| Command | Clocks | at 3.39 MHz (13.56 MHz / 4) | at 10 MHz |
|---|---|---|---|
| KeyGen with its fault checks (242,129 without) | 545,344 | 161 ms | 54.5 ms |
| KGWRAP (PUF key, KeyGen, wrap) | 587,755 | 173 ms | 58.8 ms |
| Encaps | 267,964 | 79 ms | 26.8 ms |
| Decaps (290,116 with hiding off) | 298,465 to 304,526 | 88 to 90 ms | 30 ms |
| UNWRAP, PUF key right at the first read (293,466 with the 3-read retry) | 271,738 | 80 ms | 27.2 ms |
| SEAL or OPEN, 128 bytes | 22,550 | 6.7 ms | 2.3 ms |
| ENROLL | 38,876 | 11.5 ms | 3.9 ms |

The KeyGen fault checks (section 7) add about 300 k clocks: about 250 k for the pairwise consistency test, which is an Encaps plus a partial Decaps, and about 50 k for the second computation of s, e and G. UNWRAP regenerates the key pair and runs the duplicate computation but skips the pairwise test.

The protection costs time in several places. NTT, PWM and INTT run once per share. The masked Compress takes two clocks per adder bit, about 50 clocks per coefficient for d = 10. Decaps decodes m′ a second time (about 10 k clocks). A Fisher–Yates order is drawn before each shuffled instruction (128 to 256 clocks; the next NTT layer's order is drawn while the current layer runs). The masked χ AND takes 4 clocks per lane. A PUF read takes about 15 clocks, so one key reconstruction takes about 15 k clocks and the 3- and 5-read retries about 45 k and 75 k.

## 4. Energy and low-power design

**Measurement.** `make se-power-vcd SKY130_LIB=<.lib> RAM_MACRO=1` maps the RTL to sky130_fd_sc_hd (typical, 25 °C, 1.8 V) with clock gating, runs a whole masked KeyGen on the netlist in Verilator, writes every net's toggles to a SAIF file, and has OpenSTA compute power. `scripts/power/pqse_energy.py` converts that to energy and adds the SRAM macros from their access counts. Clock tree, wires, pads and analog blocks are not included. 99.6 % of the pins were annotated in the last run.

| KeyGen (`LOWPOWER`, `CG_SRST`, with fault checks) | |
|---|---|
| Clocks in the gate-level run | 549,032 (162 ms at 3.39 MHz) |
| Energy, SRAM assumed (default `pqse_energy.py` values) | 73.5 µJ: logic 52.0 µJ, SRAM 21.5 µJ (Keccak-state and seed RAMs 19.2 µJ, polynomial RAMs 2.2 µJ) |
| Energy, SRAM from OpenRAM's analytical model (`OR_ANALYTICAL=1`) | 89.9 µJ: logic 52.0 µJ, SRAM 37.9 µJ (polynomial RAMs 19.8 µJ, Keccak-state and seed RAMs 17.6 µJ, I/O buffer 0.5 µJ) |
| Energy per clock | 133.8 to 163.7 pJ (203 pJ before the low-power RTL) |
| Average power at 3.39 MHz | 0.45 to 0.55 mW |
| Flip-flops | 7,775, of which 7,526 behind 285 clock gates |
| Setup slack at 20 ns | 7.2 ns |

Before the last clock-gating changes, 1,152 flip-flops were clocked every cycle, about 40 % of the logic energy, and KeyGen took 92.5 µJ. Plain enables on the θ column parities, the χ operands, the CSR read register, the cycle counter and the SampleNTT counters left 249 such flip-flops (small state machines and synchronizers). `build/sepower/ffs_<tag>.txt` lists the remaining ones by RTL register.

The analytical model gives 161.8 pJ per access for the 1024 x 25 polynomial RAM (assumed: 14.5 pJ per read, 22 pJ per write), 37.6 pJ for 64 x 65 (assumed: 34.5 and 54) and 103.5 pJ for 512 x 32. It uses one value for read and write and reports no leakage. An estimate of the leakage it leaves out: about 100,600 bitcells at a few pA each, under 2 µW, under 0.5 µJ per KeyGen at 3.39 MHz and 25 °C. The polynomial RAM is the figure to confirm with SPICE (`SRAM_SHAPES=a10_d25`); if it holds, splitting that RAM into smaller macros with shorter bitlines is the obvious saving.

**Low-power techniques.** None of these changes the function or the masking schedule.

| Technique | Where |
|---|---|
| Registers cleared once on going idle, then held, so they can be clock-gated | `pqse_poly`, `pqse_mcomp`, `pqse_puf`, `pqse_sponge`, `pqse_masked` |
| χ operands and DOM products (384 flip-flops) written only in the two clocks of a lane slot where they change; absorb-port registers only around an absorb | `pqse_keccak` |
| Registers that were reloaded with the same value every clock rewritten with one plain enable: the CSR read register, the cycle counter, the SampleNTT counters, the poly unit's coefficient and write-word registers | `pqse_host`, `pqse_core`, `pqse_sample`, `pqse_poly` |
| θ column parities kept in registers and updated by the χ write-back, so only round 0 needs a θ pass (35 fewer state-RAM reads and 36 fewer clocks per round). Each 64-bit lane is written with a constant index so it is clocked only when it changes; a variable part-select had made all 650 bits clocked every cycle. | `pqse_keccak` |
| Operand isolation (`PQSE_LOWPOWER`): the PRNG word, the TRNG word and the shared RAM read buses reach an engine only while it is busy | `pqse_core`, `pqse_perm` |
| Read enables only in clocks that use the data; the share-1 Keccak RAM idles in unmasked jobs | `pqse_core`, `pqse_keccak` |
| Clock gating by Yosys `clockgate`, groups of 4 or more flip-flops per enable. `CG_SRST=1` first rewrites registers with a synchronous reset over the enable to enable = en \| rst. | `make se-power*`, `CLOCKGATE=1` |

**SRAM energy.** With `RAM_MACRO=1` the RAMs are macros charged per access, and by default the energy per access is an assumption documented in `pqse_energy.py`. The published sky130 OpenRAM macros don't help: their Liberty files come from OpenRAM's analytical model, which gives one number for read, write and idle, and the smallest macro (1 KB, 32 bits wide) is much larger than the 64 x 65 Keccak and seed RAMs. Instead, `make se-sram-char OPENRAM_DIR=<OpenRAM checkout>` generates PQSE's three shapes (1024 x 25, 64 x 65, 512 x 32) with OpenRAM and characterizes them in ngspice with the sky130 models. `scripts/power/pqse_sram_char.py` turns the Liberty files into `build/sepower/openram/sram_table.txt` with pJ per read, per write and per idle clock, and the leakage. OpenRAM reports average power in mW over one cycle at the period it characterized, so energy is that power times the period. Then rerun the report with `make se-power-vcd-report ... SRAM_TABLE=build/sepower/openram/sram_table.txt`.

- OpenRAM runs through `scripts/power/openram/pqse_openram_run.py`, which keeps the energy measurements and drops the rest. It skips the minimum-period search and characterizes at a fixed `OR_PERIOD` (10 ns). It skips the leakage run of the whole untrimmed array (about 150 k transistors for 1024 x 25, the run that needed gigabytes), so the leakage column becomes the trimmed netlist's, a lower bound. It raises ngspice's step ceiling from OpenRAM's 10 ps to `OR_TMAX_PS` (50 ps), turns on the KLU solver (`OR_KLU`), and starts ngspice in `run_<shape>/` with a `.spiceinit` there, so the `OR_THREADS` setting finally takes effect. `OR_MINPERIOD=1 OR_FULL_LEAK=1 OR_TMAX_PS=10 OR_KLU=0` gives OpenRAM's own characterization. If a shape fails its delay checks, try `OR_TMAX_PS=10` first.
- `OR_SPICE=Xyce` uses Xyce instead of ngspice (MPI with `OR_THREADS` ranks when `mpirun` is on the PATH). The wrapper drops the raw file OpenRAM asks Xyce to write (every node at every step, never read) and applies `OR_TMAX_PS`; OpenRAM already selects KLU for Xyce.
- Without the full-array run only trimmed netlists are simulated, which need far less memory, so `make -j3 se-sram-char` should be able to run all three shapes at once. A finished shape leaves a stamp and is not rerun; `make se-sram-char-clean` deletes all results. After a failed run, delete `tmp_<shape>` in `OR_TMP` to free the disk space the simulator output took. `OR_TMP` is `build/sepower/openram`, or `~/.cache/pqse_openram` when the checkout is under `/mnt/` in WSL, because the Windows file system is slow for these files.
- Leave `OR_VERBOSE=0`. OpenRAM's `-v` adds `.plot V(*)` to every ngspice deck, so ngspice stores and prints every node at every time step, which runs out of memory and disk on the larger shapes.
- By default OpenRAM characterizes the schematic netlist, which has no wire capacitance, at one load and slew point. `OR_LAYOUT=1 OR_PEX=1` uses the extracted layout and also reports the area; `OR_TABLE=1` runs the full 3 x 3 load and slew table. Both are much slower.
- `OR_THREADS` sets ngspice threads (via `run_<shape>/.spiceinit`), `OR_PYTHON` the interpreter with OpenRAM's requirements, `OR_NIX=1` OpenRAM's Nix environment.
- `OR_ANALYTICAL=1` uses OpenRAM's analytical model (`analytical_delay = True`) and runs no SPICE: seconds, little memory, no ngspice needed. It gives one power for read, write and idle, computed as C·V²·f at sky130's 100 MHz event frequency, so `pqse_sram_char.py --allow-analytical` takes energy per access = power / 100 MHz and no idle energy. The numbers are rough but specific to each shape. They go to `build/sepower/openram_analytical/sram_table.txt`, apart from SPICE results.
- `SRAM_IDLE_CLOCKED=1` also charges the clocks in which a macro is idle; by default an idle macro's clock counts as gated.

## 5. Side-channel countermeasures

| Threat | Countermeasure | Files |
|---|---|---|
| Timing | Fixed schedule: no branch, address or loop count depends on a secret. Branches only on public results (input checks, tags, the PUF check value). Implicit rejection is a masked select. | `pqse_ucode.v`, `pqse_masked.v` |
| Power and EM analysis of Decaps (static key, chosen ciphertexts), KeyGen, Encaps and repeated UNWRAP | Every secret is two shares. ŝ, e, y, e₁, e₂ are arithmetic shares mod q and run NTT, INTT and PWM per share. Seeds, m′ and K are Boolean shares. G, J, PRF and KMAC run on the masked Keccak; the CBD sampler, Compress, the comparison c′ = c and the select are masked gadgets. m′, r′, K′, K̄ and the comparison result are never unmasked. t̂ and c are unmasked only as public outputs. | `pqse_mcomp.v`, `pqse_masked.v`, `pqse_keccak.v`, `pqse_ucode.v` |
| Side-channel attacks on re-encryption (plaintext-checking oracles, Ravi et al. TCHES 2020, Ueno et al. TCHES 2022) | No unmasked m′, no unmasked comparison bit, no early abort. | as above |
| Glitches and transitions | The gadget rules in section 6, checked by `make se-probe`. | gadgets, `pqse_io.v`, `pqse_sponge.v`, `pqse_core.v` |
| Single-trace attacks on the NTT (Primas et al. CHES 2017); profiled attacks on message decoding with repeated Decaps of one ciphertext (masked FPGA Kyber broken with about 400 traces and a majority vote, ASHES 2023 / JCEN 2025) | A fresh uniformly random order (inside-out Fisher–Yates) for each PWM, ADD, MSPLIT, Compress, μ and CBD instruction, and for each NTT and INTT layer. 0 to 15 random dummy clocks before each engine start. | `pqse_perm.v`, `pqse_poly.v`, `pqse_core.v` |
| Fault attacks | Section 7. | |
| Reading keys through the interface | No command outputs dk, ŝ, z, m′, the KEK, or K in USER. The buffer is reachable only while idle, through fixed windows. Temporaries are wiped after every command, engine registers cleared when idle, the Keccak state cleared between hash jobs, and a power-on wipe clears RAM left over from before a reset. | `pqse_host.v`, `pqse_ucode.v` |
| Debug features in the field | Injected seeds, raw dumps and the trigger pin only in TEST; key import and PUF enrollment only in TEST or PERSO; the lifecycle only moves forward. | `pqse_host.v`, `pqse_top.v` |
| Physical tamper | The tamper input aborts the command, wipes every key and moves to KILLED. A chip ORs its sensors into this input (clock and voltage glitch, temperature, light, active shield); those are analog cells from the PDK or an IP vendor, outside this RTL. | `pqse_host.v` |
| Weak randomness | Ring-oscillator TRNG with the SP 800-90B repetition-count, adaptive-proportion and start-up tests, conditioned by SHA3-256. Trivium PRNG reseeded per command, with a hardware check against reused mask words. A TRNG failure gives result 5; ZEROIZE still runs. | `pqse_rng.v` |

## 6. Masked gadgets

All gadgets are first-order and follow five rules, which the probing check enforces: shares meet only in registered DOM cross terms; every DOM result passes through a compress register before it is used again; a value is unmasked only from two registers that nothing else loads; RAM words are read in the order share 0, public word, share 1, with both RAM output registers precharged between instructions; and a register behind the read bus never holds one share while the bus carries the other.

- **Arithmetic shares mod q** (ŝ, e, y, e₁, e₂, w, u, v): x = x₀ + x₁ mod q. Share 0 lives in even slots (RAM 0), share 1 in odd slots (RAM 1). Linear operations run per share.
- **Masked CBD (B2A)**, `pqse_masked.v`. The masked sponge writes the PRF output as Boolean shares, one per seed RAM, into scratch entries E_CBD (12 to 15). M_CBD reads one 8-bit word (two coefficients) at a time in the random order and converts each bit b = b₀ ⊕ b₁ of weight v with one fresh R mod q: T = v·b₀ − R (registered), then A₀ = b₁ ? −T : T and A₁ = b₁ ? v − R : R, so A₀ + A₁ = v·b. The weights are +1, +1, −1, −1 for the CBD and 1665 for μ. The word writer reads share 0, a public word, then share 1, and writes each share from its own register.
- **Compress_d** (d = 1, 4, 10), `pqse_mcomp.v`. Each share is scaled on its own, y_s = round(x_s · 2^K / q) mod 2^K with K = d + 14 and 2¹³ added to share 0. The top d bits of y₀ + y₁ are Compress_d(x). The sum is a bit-serial ripple-carry adder on the Boolean sharings a = (y₀⊕R, R) and b = (R′, y₁⊕R′), two clocks per bit: a DOM AND with four registered partial products, then the carry shares are compressed into registers, carry′ = a ⊕ ((a⊕b) ∧ (a⊕c)). The partial products reload every clock and are 0 outside the compress clock, because a held cross term next to the carry share that contains its random bit would unmask it. Output mode 0 writes m′ as Boolean shares to a seed entry; mode 1 compares each bit with the public ciphertext bit and ANDs the result into `ok`; mode 2 outputs the ciphertext bit, unmasked from two registers only this mode loads.
- **Comparison.** `ok` is a Boolean-shared bit kept in two copies with independent randomness. Each update is a DOM AND (partial products reloaded every clock) followed by a compress clock. OKCHK unmasks only ok_a ⊕ ok_b, which is 0 unless a fault hit one copy. OKOUT, used only for tag checks, copies the shares into two registers that nothing else loads and combines them there.
- **Select.** K = K̄ ⊕ (ok ∧ (K′ ⊕ K̄)), one DOM AND per bit. The result stays masked in seed entry E_SK.
- **Keccak χ.** X = ¬a[x+1] and Y = a[x+2], one DOM AND per bit with 64 fresh random bits per lane. Per lane: read a[x+1] into X, read a[x+2] into Y, AND, then write a[x] ⊕ products back. X is cleared after the AND and Y and the products reload every clock, so the AND never sees both shares of one lane, even across consecutive clocks. That makes any lane order safe; the RTL uses 0, 2, 4, 1, 3.
- **IO_SEQ.** e ⊕ e₂ is computed per share into registers and the two differences are compared. The result is 0 unless a fault hit one of the two values, and the secret itself is never combined.

**Probing check** (`scripts/pqse_probe_verify.py`, `make se-probe`, also run by `make sim-se`). Each gadget is simulated clock by clock with the RTL's schedule. A probe on a wire sees every register in its combinational cone, every input of every multiplexer in that cone, and a register's own value when its load is a data multiplexer, in the probed clock and the clock before (the robust probing model with glitches and transitions). For each probe and clock, the checker computes the exact distribution of what the probe sees over all masks and random bits, and compares it across all secret values. Covered: the Compress adder (m′ and compare modes, the latter with the ok accumulator), the two ok copies with OKCHK, SEL, the B2A, a χ slice, IO_SEQ, and the RAM read port with the registers behind it. Negative controls (the v2 adder, ok accumulator, χ and read port; v3's χ with the natural lane order; an adder draft with held partial products; χ with held operands) must be reported as leaking. The check works on each gadget's registers and schedule; the synthesized netlist needs a netlist-level tool such as PROLEAD.

## 7. Fault detection and response

| Detector | Catches | Files |
|---|---|---|
| Program counter with a complemented shadow | skipped or repeated instructions | `pqse_core.v` |
| Complemented shadows of the sequencer state, the Keccak pass, round, column, plane and lane counters, and the sponge state and return state, written in the same statements and compared every clock | a flipped control bit: skipped Keccak rounds (a wrong hash that parity can't see), a sequencer stopped in idle mid-command, a jump between sponge states | `pqse_core.v`, `pqse_keccak.v`, `pqse_sponge.v` |
| Instruction parity, computed at fetch and checked at execute | a corrupted instruction register | `pqse_core.v` |
| Engine-ran check | an engine start that was suppressed (the engine never reported busy) | `pqse_core.v` |
| Even parity on every polynomial, seed and Keccak-state RAM word and on each θ column-parity register, checked per share on every read | bit flips in stored keys, intermediates and hash state | `pqse_core.v`, `pqse_keccak.v` |
| Two masked `ok` copies and OKCHK | a fault that forces "c′ = c" or skips part of the comparison | `pqse_masked.v` |
| m′ decoded twice (fresh masks, fresh order), compared with IO_SEQ | a fault in one decoding of m′ | `pqse_ucode.v`, `pqse_io.v` |
| PRNG freshness check | a mask word used twice, which would weaken the masking with no visible error | `pqse_rng.v` |
| Host watchdog: a command or wipe still running after 2²² clocks | a hang that nothing else sees | `pqse_host.v` |
| KeyGen duplicate computation (microcode 720) | a fault that changes ek and dk consistently | `pqse_ucode.v`, `pqse_poly.v` |
| KeyGen pairwise consistency test (microcode 608) | a fault that makes ek and dk disagree | `pqse_ucode.v` |
| Complemented shadows of the lifecycle, fault counter and tampered flag; a persistent store written ahead of every change | a flipped security-state bit; resetting the fault count or KILLED by a power cycle; a lifecycle rolled back | `pqse_host.v` |

**PRNG freshness.** Trivium runs 32 rounds per clock into a 64-bit word, so a word is completely fresh two clocks after the previous take. Consumers that take on consecutive clocks (B2A, SEL, the adder's AND clock, the ok copies) use only the top half, which is always fresh. The hardware check (`ferr`) raises FAULT if any other word is taken early.

**Watchdog.** 2²² clocks is about 84 ms at 50 MHz and 1.2 s at 3.39 MHz; the longest command, KGWRAP, needs about 0.59 M clocks. The watchdog sits in the host because a stopped core also stops its own cycle counter. A hung command is handled like a detected fault; a hung wipe moves the chip to KILLED.

**KeyGen duplicate computation.** Every secret polynomial s₀..s₂, e₀..e₂ is produced twice (PRF, masked CBD, NTT), the second time with fresh masks and its own word orders. The NTT-domain copies are compared without unmasking: SUB per share, then ZCHK, a poly-unit operation that raises FAULT unless the two share differences sum to 0 mod q for every coefficient. Equal copies leave (r, −r), where r is a difference of fresh masks, so nothing about the polynomial is combined. G(d‖3) also runs twice: the second result is XORed into the first, which must give zero (IO_SEQ against the zero entry E_KB), and ρ in the buffer is compared with G's. This runs on every key derivation (KEYGEN, KGWRAP, UNWRAP). It catches what the pairwise test can't: faults in G, a PRF, the CBD or an NTT of s or e change ek and dk together. Examples are a coefficient off by a few, a polynomial forced to zero (a weak key), and two secret polynomials made equal by a PRF nonce fault (a known key-recovery attack on ML-KEM KeyGen).

**KeyGen pairwise consistency test** (FIPS 140-3). Before the key is marked valid, the microcode runs a masked Encaps of a fresh random m to the new ek (read back from the buffer, with its own H(ek)), then decapsulates that ciphertext with the new ŝ and h, and compares K and K′ share-wise with IO_SEQ. Its ciphertext stays in the output window; that is harmless because its K never leaves the chip. It catches faults that make ek and dk disagree (a corrupted t̂, ŝ or H(ek)). Faults after the duplicate comparison, in the PWM, the unmasking or encoding of t̂, or in the stored ŝ, are NTT-domain changes, which become a dense, large error in the time domain, so the test's decoding fails.

**Persistent store** (`pqse_nvm` in `pqse_host.v`). Lifecycle, fault count and tampered flag as set-only thermometer bits in two OR-combined copies, loaded at reset. A fault, kill or tamper event is programmed before the next command is accepted. A store that is ahead of the registers (a rollback) is handled like the tamper input.

**Response.** The command ends with result 8 (FAULT). The host resets every engine, runs ZEROIZE and increments the fault counter (STATUS[18:17]); the third fault moves the lifecycle to KILLED. Keys must then be unwrapped or re-imported. A fault whose only effect is a wrong value inside the masked re-encryption ends as an implicit rejection (a random-looking K̄), and the kill after three detected faults limits what a statistical fault attack can collect.

## 8. PUF and key wrapping (`pqse_puf.v`)

**Cells.** The response comes from 960 SRAM-type cells in 30 rows of 32. An SRAM cell's power-up value is decided by the mismatch of its two cross-coupled inverters, the best-studied PUF in smart cards. Each cell belongs to exactly one response bit. The source module `pqse_puf_raw` has four builds:

- `PQSE_PUF_LATCH`, for the FPGA prototype and an open-PDK chip. Each cell is two cross-coupled NAND gates (`pqse_pufcell`). A read forces both nodes of a row high, releases them, waits 8 clocks for the cells to settle and samples through a synchronizer. Every read repeats the power-up race, so majority voting over 3 or 5 reads works. Cost: 2 gates per bit, about 0.01 mm² in SKY130 (an OpenRAM 1 KB macro is about 0.2 mm²), about 2 k LUTs on the FPGA.
- `PQSE_PUF_BFLY`, a butterfly cell (`pqse_bflycell`, Kumar et al., HOST 2008) built from two transparent latches in the logic cells' flip-flops, one with an asynchronous clear and one with a preset. It uses about 2,880 flip-flops and no LUTs on the GW2AR-18 (`make se-gowin PUF=bfly`). Each cell takes the row's excite through its own flip-flop, because GowinSynthesis otherwise merges the 32 identical cells of a row. Butterfly cells are known for routing bias, so measure them with PUFRAW. Intel parts have no latch mode in their registers; keep `PQSE_PUF_LATCH` on the DE10-Nano.
- `PQSE_PUF_SRAM`, the power-up contents of a dedicated 32 x 32 SRAM macro that nothing writes (`pqse_puf_sram`, a black box). It gives one sample per power-up, so the retries add nothing and the code alone must cover the bit-error rate.
- Default: a simulation model with a fixed device pattern, read noise, drift and a noisy mode.

FPGA block RAM can't serve as the PUF on Gowin parts because the bitstream initializes it.

**Code.** Reed–Muller RM(1,5) = [32, 6, 16] in a code-offset fuzzy extractor: 6 key bits per 32 response bits, correcting up to 7 errors per block. 30 blocks give a 180-bit key and 120 bytes of helper data. The helper data leaks up to 26 bits per block, so the key keeps 30 · (32h − 26) bits for a min-entropy of h per response bit, and 128 bits need h ≥ 0.946. One device's 960 bits can't show that at 99 % confidence (that takes about 4,500 bits, about 5 devices), so measure several boards or chips and raise `PUF_NB` if h is lower.

**Enroll** (TEST or PERSO). A key k comes from the TRNG into a masked seed entry. Each response bit is read 5 times and majority-voted for a clean reference r. Helper data w = r ⊕ C(k) is built in two clocks per bit: r ⊕ C(k₀) is registered first and C(k₁) added after, so no gate sees C(k₀) ⊕ C(k₁). The microcode then stores the check value H(k‖"C") (the first 8 bytes of SHA3-256, from the masked sponge) in the 16th helper lane.

**Reconstruct.** One read per bit. With a fresh random 6-bit R per block the decoder sees y = r′ ⊕ w ⊕ C(R) = C(k ⊕ R) ⊕ e and decodes k ⊕ R by maximum likelihood, so the key comes out as the shares (k ⊕ R, R) and is never unmasked in the decoder. The 32 bits of a block are read in a random order. The microcode hashes the key (masked) and compares the check value. On a mismatch it reconstructs again with the majority of 3 reads per bit, then 5; if that also fails, the result is 12.

**Wrapping.** KEK = SHA3-256(k_PUF ‖ "K"). The 64-byte seed d‖z is stored as blob = nonce ‖ (d‖z ⊕ SHAKE256(KEK‖nonce)) ‖ SHA3-256(KEK‖nonce‖ct), 112 bytes.

**Failure rates and drift.** `pqse_model.py` check 7 runs a Monte Carlo of the real decoder at 5 to 20 % bit errors per read. At 10 %, single reads lose the key in a large share of unwraps and the retries lose it in none of the samples. Majority voting only removes read noise; bits that flip for good are left to the code. The testbench flips 9.4 % of the bits permanently (unwrap still works) and adds 20 % read noise (the retry recovers the key). PUFRAW dumps 960 single-read bits; `scripts/pqse_puf_stats.py` reports uniformity, bit-error rate, inter-device distance, failure rates with and without retries, and the entropy left after the helper data.

## 9. Session key and secure messaging

ENCAPS (initiator) and DECAPS (responder) keep the shared secret K, masked, as the session key SK in seed entry E_SK (STATUS[16] = loaded). In TEST and PERSO they also copy K to the buffer for known-answer tests; in USER K never leaves.

| Command | Buffer in | Buffer out |
|---|---|---|
| SEAL | message M at `B_SM_MSG`, its length L (1 to 128) in header lane 1 | header H (32 bytes) = counter (8 bytes LE) ‖ L (8 bytes LE) ‖ 16 zero bytes; C = (M[0..L−1] ⊕ KMACXOF256(SK, H, 1024, "E"d)) padded with zeros; T = KMAC256(SK, H ‖ C, 256, "T"d). Result 1 if L is out of range; no counter is used. |
| OPEN | H ‖ C ‖ T | M (bytes from L on are 0). Result 11 (REPLAY) for a counter already accepted or more than 63 behind the newest; result 9 (BADTAG) for a bad length or tag, with C left encrypted. |

d is "1" from initiator to responder and "2" the other way, so a message reflected back to its sender fails. The keystream and tag come from the masked sponge with the masked SK as key; only C (or M) and T are unmasked, from registers that only the keystream sink loads.

**Replay protection.** Each side keeps the counter of its next outgoing message and a 64-message window of accepted counters: the newest accepted counter plus one bit for each of the 63 before it. A new session key resets both. SEAL increments the counter before computing the keystream, so an aborted command never reuses a counter. OPEN rejects a counter that was already accepted or is older than the window, then checks the length and the tag, and marks the counter only for an authentic message, so a forgery can't burn a counter. Lost and reordered messages inside the window are accepted once. `scripts/pqse_sm_check.py` recomputes C and T for every sealed message with its own KMAC, which is itself checked against hashlib and the SP 800-185 examples.

## 10. Interface

**Registers** (32-bit words, `pqse_host.v`):

| Address | Register | Contents |
|---|---|---|
| `0x400` | ID | "PQSE" = `0x50515345` |
| `0x401` | VERSION | `0x00040000` |
| `0x402` | CTRL | [7:0] command, [8] use injected seeds (TEST only). Writing starts the command. |
| `0x403` | STATUS | [0] busy, [1] done (write 1 to clear), [2] key loaded, [3] TRNG ok, [4] TRNG failed, [5] tampered, [7:6] lifecycle, [15:8] result, [16] session key loaded, [18:17] faults detected |
| `0x404` | CYCLES | clocks taken by the last command |
| `0x405` | LIFECYCLE | write a later state to move forward (0 TEST, 1 PERSO, 2 USER, 3 KILLED) |
| `0x406` | CONFIG | [0] hiding on (default 1) |

After reset the device is busy for about 3 k clocks while the power-on wipe runs; wait for STATUS[0] = 0.

**Pins.** SPI (4), IRQ, tamper input, and `trig`. The trigger output is high during the masked comparison window (OKINI to OKCHK: in DECAPS the whole secret part, in OPEN and UNWRAP the tag check), only in lifecycle TEST, so a deployed device gives no timing reference. On the DE10-Nano it is GPIO_0[0] and LED1.

**Buffer.** Words `0x000` to `0x3FF`; word w is half (w & 1) of 64-bit lane (w >> 1).

| Lanes | Contents | Host access |
|---|---|---|
| 0 to 147 | own ek | read; write in TEST and PERSO |
| 148 to 163 | PUF helper data (120 bytes) and key check value (8 bytes) | read, write |
| 164 to 311 | input: peer ek, ciphertext, ŝ bytes | write |
| 312 to 447 | output: ciphertext, raw dumps | read |
| 448 to 451 | K | read in TEST and PERSO |
| 452 to 467 | injected d (TEST), z, m (TEST), H(ek) | write in TEST and PERSO |
| 468 to 481 | wrapped-key blob (112 bytes): nonce 2 lanes, ciphertext 8, tag 4 | read, write |
| 484 to 507 | secure message (192 bytes): header 4 lanes (counter, length, 0, 0), M or C 16, T 4 | read, write |

**Commands** (CTRL[7:0]):

| # | Command | Inputs | Outputs | Allowed in |
|---|---|---|---|---|
| 1 | KEYGEN | (TEST: d, z) | own ek | all but KILLED |
| 2 | ENCAPS | peer ek (TEST: m) | c, session key (initiator); K in TEST/PERSO | all but KILLED |
| 3 | DECAPS | c | session key (responder); K in TEST/PERSO | all but KILLED, needs a key |
| 4 | IMPORT | ŝ bytes, ek, H(ek), z | none | TEST, PERSO |
| 5 | ENROLL | none | PUF helper data and check value (128 bytes) | TEST, PERSO |
| 6 | KGWRAP | PUF helper data | own ek, blob (112 bytes) | all but KILLED |
| 7 | UNWRAP | blob, helper data | own ek (regenerated) | all but KILLED |
| 8 | ZEROIZE | none | none | all but KILLED |
| 9 | SEAL | message, length | H, C, T | all but KILLED, needs a session key |
| 10 | OPEN | H, C, T | message | all but KILLED, needs a session key |
| 11 | PUFRAW | none | 960 PUF bits (lanes 312 to 326) | TEST |
| 12 | TRNGRAW | none | 136 TRNG words (lanes 312 to 447) | TEST |

**Result codes** (STATUS[15:8]): 0 OK, 1 bad input (ek modulus check, dk hash check, message length), 2 denied by the lifecycle, 3 no key, 4 bad blob, 5 TRNG failure, 6 unknown command, 7 KILLED, 8 FAULT, 9 bad tag or length (OPEN), 10 no session key, 11 replay (OPEN), 12 PUF key not reconstructed.

**SPI** (mode 0, SCK at most clk/4). Write: `02 aH aL`, then 4 bytes per word, least significant byte first. Read: `03 aH aL xx`, then 4 bytes per word.

## 11. Microcode map

The ROM holds 1024 instructions of 96 bits. Instruction classes: END, BR (branch on a flag), SET (status flags, reseed), HASH (a whole sponge job: sources, padding, rate, masked or not, sink), POLY, IO, MASK, PUF.

| Address | Program |
|---|---|
| 0 to 8 | failure exits (8: a KeyGen check failed, result FAULT) |
| 16 | KEYGEN / KGWRAP: seeds from the TRNG (or injected in TEST); KGWRAP first reconstructs the PUF key |
| 32 | UNWRAP: PUF key, KEK, tag check, decrypt d‖z |
| 48 | PUF key with check value and retries, then KEK (shared by KGWRAP and UNWRAP) |
| 80 | KeyGen core, masked (s and e at 720) |
| 144 | wrap (KGWRAP only) |
| 156 | KeyGen end: wipe temporaries |
| 192 | ENCAPS |
| 320 | DECAPS (m′ decoded twice and compared at 341, ok copies compared) |
| 448, 480 | SEAL, OPEN |
| 512, 528 | IMPORT, ENROLL |
| 544, 548 | PUFRAW, TRNGRAW |
| 560 | ZEROIZE (also the power-on wipe, 560 to 602) |
| 608 | KeyGen pairwise consistency test (K compared at 698) |
| 720 | KeyGen s and e computed twice and compared (ZCHK at 733, 744, 755, 766, 777, 788); G check at 790 and 791 |

## 12. Files

| File | Contents |
|---|---|
| `pqse_top.v` | `pqse_top` (chip: SPI, IRQ, tamper, trigger), `pqse_avalon` (FPGA), `pqse_sys` |
| `pqse_host.v` | registers, lifecycle, access windows, command and K-export policy, fault counter, watchdog, wipes; `pqse_nvm` persistent store |
| `pqse_spi.v` | SPI slave |
| `pqse_core.v` | sequencer (10-bit pc) with fault checks and RAM-port precharge, share-domain RAMs with parity, TRNG and PRNG, trigger, port multiplexing |
| `pqse_ucode.v` | microcode for every command |
| `pqse_keccak.v` | masked lane-serial Keccak-f[1600], state in two RAMs |
| `pqse_sponge.v` | sponge controller: sources, padding, KMAC, sinks (including the message keystream) |
| `pqse_sample.v` | SampleNTT (`pqse_parse`) and an unmasked CBD sampler that is not instantiated |
| `pqse_poly.v` | NTT, INTT, PWM, ADD, SUB, MSPLIT, ZERO, ZCHK with shuffling |
| `pqse_perm.v` | Fisher–Yates permutation in a 128 x 7 register file |
| `pqse_io.v` | encode, decode, seed-register operations (including SEQ), message header, length and replay window, raw TRNG dump |
| `pqse_mcomp.v` | masked Compress_d: m′, compare and ciphertext modes |
| `pqse_masked.v` | masked CBD (B2A), μ, select, the two ok accumulators, tag check |
| `pqse_puf.v` | PUF cell arrays, simulation model, RM(1,5) fuzzy extractor with masked decoding, raw dump |
| `pqse_rng.v` | ring-oscillator TRNG with health tests, Trivium PRNG with freshness check |
| `pqse_arith.v`, `pqse_mem.v`, `pqse_defs.vh`, `pqse_func.vh` | modular arithmetic, RAM models, constants |
| `pqse_avalon_hw.tcl` | Platform Designer component |
| `../sim/tb_pqse.sv` | functional testbench (17 groups) |
| `../sim/tb_pqse_fault.sv`, `../../scripts/pqse_fault_report.py` | fault campaign and its report |
| `../sim/tb_pqse_tvla.sv`, `../../scripts/pqse_tvla.py` | TVLA testbench; ciphertext generator, report, two-run confirmation, board mode |
| `../sim/tb_pqse_gate.sv`, `../../scripts/pqse_lib2v.py` | gate-level power testbench; cell models from the Liberty file |
| `../../scripts/pqse_probe_verify.py` | probing check of the masked gadgets |
| `../../scripts/pqse_model.py` | gadget, fuzzy-extractor, retry and shuffle arithmetic |
| `../../scripts/pqse_sm_check.py` | independent KMAC check of sealed messages |
| `../../scripts/pqse_puf_stats.py` | PUF and TRNG statistics, failure rates from a measured bit-error rate |
| `../../scripts/pqse_power.tcl` | OpenSTA power and timing script |
| `../../scripts/power/` | SRAM macro wrapper and counting models (`RAM_MACRO=1`), OpenRAM configs, SRAM table, energy and flip-flop reports |
| `../../scripts/pqse_fit.py` | Tang Nano 20K fit report from Yosys `synth_gowin` |
| `../../quartus/jtag/` | DE10-Nano top (KEY1 = tamper, GPIO_0[0] = trigger), System Console demo, TVLA capture |

## 13. Make targets

```bash
make sim-se                      # model and probing checks, RTL testbench, KMAC check, PUF/TRNG stats
make sim-se TRACE=1              # also prints every microcode instruction
make se-probe                    # probing check alone (--full: larger widths)
make sim-se-tvla MASKED=1 N=200  # TVLA of masked Decaps on a power model (expect no leak)
make sim-se-tvla MASKED=0 N=200  # positive control (expect leaks)
make sim-se-fault FN=200         # fault campaign on Decaps (FOP=keygen for KeyGen); expect no SILENT
make se-area                     # Yosys gate count; SKY130_LIB=<.lib> maps to SkyWater 130 nm
make se-power SKY130_LIB=<.lib>  # vectorless power (activity 0.1) and the slowest path; RAM_MACRO=1: logic only
make se-power-vcd SKY130_LIB=<.lib> RAM_MACRO=1   # energy of one KeyGen from a gate-level run (GL_CMD=2: Encaps)
make se-power-sample SKY130_LIB=<.lib> RAM_MACRO=1 GL_FMT=vcd GL_CLOCKS=<n>   # the same from 8 sampled 2000-clock windows
make se-sram-char OPENRAM_DIR=<OpenRAM checkout>       # SPICE energy of the SRAM shapes (section 4)
make se-gowin                    # Tang Nano 20K fit (GW2AR-18); PUF=0 without PUF cells, PUF=bfly butterfly cells
make se-gowin-eda                # the same with Gowin EDA synthesis and place and route
cd quartus/jtag && quartus_sh -t build.tcl se    # DE10-Nano, then source pqse_test.tcl
```

## 14. Testbenches

**Functional** (`tb_pqse.sv`, 17 groups). NIST KeyGen and Encaps known answers through the masked datapath. Masked Decaps, valid and implicit rejection, on imported NIST keys with hiding on and off. A round trip, the ek and dk input checks. PUF enroll, wrap, zeroize and unwrap, unwrap after 9.4 % drift, a 20 %-noise PUF recovered by the retry, a wrong check value (result 12), a modified blob. SEAL and OPEN between the two roles with lengths 128, 100 and 1, bad lengths, out-of-order delivery, replays, a counter older than the window, modified ciphertext, length or padding, reflection, and no session key after ZEROIZE. Raw dumps. The USER rules (no trigger, no K). Persistence of the lifecycle, fault count and tamper flag across power cycles. SPI and tamper. And 17 directed fault and tamper injections, each of which must end in FAULT or KILLED with the keys wiped:

- program-counter shadow; one ok copy; a double-bit error in m′ that only the second decoding catches; RAM parity after a power cycle; tamper input;
- a Keccak state bit and a θ column-parity bit mid-permutation; a flipped lifecycle bit; a lifecycle rolled back below the store;
- the Keccak round counter; a sponge state bit; a sequencer state bit; a hung command (watchdog); a stale PRNG word;
- a dk corrupted after ek was computed (pairwise test); a parity-blind Keccak fault during G(d‖3) (G check); a small change to one coefficient of s₀ after the sampler (duplicate compare).

**Fault campaign** (`tb_pqse_fault.sv`, `scripts/pqse_fault_report.py`). Each run starts a new chip from a power cycle with the persistent store cleared, then flips one bit in one of 38 targets at a random clock of a NIST-vector Decaps or KeyGen. Targets include the program counter and its shadow, the instruction register, the engine state machines, the PRNG freshness counter, the lifecycle, fault counter and persistent store, Keccak control, datapath, column parities and state RAMs, the comparison copies and gadget registers, the compression, poly and I/O registers, and the polynomial and seed RAMs, both shares. Outcomes are unchanged, detected (FAULT, wiped and counted), implicit rejection (Decaps returned K̄ = J(z‖c), which is harmless), SILENT (a wrong output with result 0, the outcome an attacker wants) and hang (past the watchdog, which the campaign shortens to 2²¹ clocks, so a hang means the watchdog failed). The report names the target of any silent outcome.

| Campaign, 200 runs | unchanged | detected | implicit rejection | silent | hang |
|---|---|---|---|---|---|
| Decaps | 111 | 74 | 15 | 0 | 0 |
| KeyGen | 127 | 73 | n/a | 0 | 0 |

**TVLA** (`tb_pqse_tvla.sv`). Fixed-versus-random m with random coins, so only Decaps' secret intermediates differ between the two classes; hiding off, lifecycle USER. The power model counts, per clock, the toggling bits in the RAM buses and in the datapath, gadget, unmasking and Keccak registers. Welch's t is computed per clock; |t| > 4.5 marks a candidate leak, reported by microcode address with the chance level. `pqse_tvla.py confirm` applies the two-run rule: a leak counts only if it appears at the same point in two independent runs.

**On the board** (`quartus/jtag/pqse_tvla_capture.tcl`). `pqse_tvla.py gen` makes the ciphertext set. The script imports the NIST key and runs one Decaps per ciphertext with the trigger on GPIO_0[0]; an oscilloscope in segmented mode records one trace per run (EM probe over the FPGA or a shunt in the core supply). `pqse_tvla.py board traces.npy tvla_in.txt` computes t per sample (`--align` for jitter or hiding on), and `confirm` applies the two-run rule.

## 15. Verification you run, in this order

1. `make sim-se`: expect `TEST PASSED`, `SM CHECK PASSED`, `PROBING CHECK PASSED`, `MODEL CHECKS PASSED`.
2. `make sim-se-tvla MASKED=1 N=200`, again with `SEED=2`, then `pqse_tvla.py confirm`. `MASKED=0` must show leaks.
3. `make sim-se-fault FN=200` and `FOP=keygen`: no SILENT, no hang.
4. `make se-gowin` (must say "fits"), `make se-area`, `make se-power SKY130_LIB=...` with `MASKED=1` and `0` for the cost table; `make se-power-vcd SKY130_LIB=... RAM_MACRO=1` for energy (Verilator 5.036 or newer).
5. On the DE10-Nano: `build.tcl se`, `pqse_test.tcl` (all PASS), PUFRAW and TRNGRAW dumps from several boards through `pqse_puf_stats.py`, then a board TVLA.
6. Before a tape-out: a netlist-level probing check of the synthesized gadgets (PROLEAD).

## 16. When `make sim-se` fails

1. **Compile errors:** `build/sesim/build.log`.
2. **`pqse_model.py` or `pqse_probe_verify.py` fails:** the gadget in the named file no longer matches its model. The probing check prints the probe and clock.
3. **Stuck busy after reset:** the power-on ZEROIZE (`TRACE=1` shows pc 560 to 602).
4. **FAULT (result 8) with nothing injected:** `TRACE=1` prints which detector fired: ctl, engine, parity, keccak, okchk, decoder, prng or zchk.
   - decoder: the two m′ decodings in Decaps disagree. Check the share-wise SEQ and that both Compress_1 runs read the same accumulator slots.
   - zchk at pc 733, 744, 755, 766, 777 or 788: the two copies of s₀..s₂, e₀..e₂ differ. At 790 or 791: the G recompute check. At 698: the pairwise test (K ≠ K′; compare its Encaps and Decaps with the plain ones at 192 and 320).
   - keccak: a parity error, or a control register assigned without its shadow.
   - prng: a consumer took a word less than two advances after the previous take.
5. **KeyGen ek wrong:** check Keccak alone first. With `TRACE=1` the first HASH is H(ek); a wrong SHA3 points at `pqse_keccak.v` (pass order TH, RP, CHI; the `pdst` and `rho` tables; the χ write-back one clock after the AND; ι on lane 0). Then the sponge's read latency (`H_SKX`, `H_STRV`), the masked CBD into two slots, `padd` of the t̂ shares, an NTT then INTT round trip, PWM.
6. **Encaps wrong, KeyGen right:** the Compress output mode (`so0`/`so1` to WL/WH bit position, lane count) or the XOF byte order (ρ‖i‖j).
7. **Decaps wrong:** run with `MASKED=0`. If that passes, the bug is in a gadget (B2A weights, `neg1`, reader bit order, the ok compress clock).
8. **SEAL or OPEN:** `pqse_sm_check.py` names the wrong part (header, ciphertext or tag) after checking its own KMAC. For a KMAC mismatch, look at the constant lanes `KM_A0`, `KM_PRE` and the customization string in `pqse_sponge.v`.
9. **UNWRAP result 12:** the check-value lane (helper lane 15, buffer lane 163) or `h_kchk`. Result 4: the tag.
10. **Hang (TIMEOUT):** `TRACE=1` shows the last instruction, usually a sink that never reports done or the sponge waiting for TRNG words.

## 17. Scope and limits

The masking is first order, shown for each gadget's registers and schedule in the robust probing model with glitches and transitions. Hiding adds noise against higher-order and horizontal attacks. The simulated TVLA and the gadget-level probing check don't see what synthesis does to the netlist or coupling inside SRAM macros; the board TVLA and a netlist-level check cover that.

On the FPGA, the latch PUF and the ring-oscillator TRNG demonstrate the interfaces and post-processing; FPGA routing makes the latch cells more biased than on silicon. The persistent store's behavioural model survives a reset but not an FPGA power-off (Gowin GW1NR and GW2AR parts could use their user flash). A chip replaces `pqse_nvm` with an OTP or eFuse macro wrapper with the same ports.

Two alternatives were considered and not taken. Second-order masking of Decaps would generalize the same gadgets (DOM with three shares) at roughly 3 to 4 times the area and time. Ascon-AEAD128 (SP 800-232) would make secure messaging smaller and faster per message but needs a second masked permutation, while KMAC reuses the masked Keccak that ML-KEM needs anyway. ML-DSA (FIPS 204) signatures on the same Keccak and polynomial datapath would be a natural extension for document signing.

## 18. Version history

**v4 (this version)** targets a contactless card. v3 needed 44 k LUT4s on the Tang Nano 20K's GW2AR-18, twice the device. v4 moved the Keccak state from about 5,100 flip-flops into two RAMs, put the microcode in a ROM with a registered read, replaced the 1,920 ring-oscillator PUF with SRAM-type cells, made encode and decode bit-serial, and slowed Trivium from 64 to 32 rounds per clock. Later v4 work added the low-power RTL and clock gating and the fault hardening: control-register shadows, the watchdog, the PRNG check, the KeyGen duplicate computation and the pairwise test.

**v3** moved the shuffle table into a register file and gave every NTT layer its own random order. It added the probing check, which found five leaks in v2's gadgets that v3 fixes: the adder carry and ok accumulators reused DOM results without a compress register, the adder's partial products held their value next to a carry share masked by the same random bit, unmasking XORs saw both shares all the time, the χ operands came from plane multiplexers holding both shares, and the read multiplexer could hold both shares of a coefficient. v3 also added the PUF check value and majority retry, the second decoding of m′, KMAC-based secure messaging with a replay window, the 1024-entry ROM, and the trigger pin and board TVLA flow.

## 19. Names used in the RTL

| Name | Meaning |
|---|---|
| share, share domain | one of the two random parts of a masked value; "domain 0" is all logic that handles share 0 |
| DOM | domain-oriented masking (Groß et al. 2016): an AND of two shared values computed as four partial products, the two cross terms refreshed with a random bit, all registered before they are combined |
| compress register | the register that combines a DOM AND's partial products back into two shares |
| B2A | Boolean-to-arithmetic conversion: from shares with x = x₀ ⊕ x₁ to shares with x = x₀ + x₁ mod q |
| CBD | centered binomial distribution, the sampler for ML-KEM's small secret and error polynomials |
| PRF, G, H, J | the ML-KEM hash functions (SHAKE256, SHA3-512, SHA3-256, SHAKE256) |
| NTT, INTT, PWM | number-theoretic transform, its inverse, and pointwise multiplication in the NTT domain |
| BFU | butterfly unit: one add, one subtract and one multiply of the NTT |
| MSPLIT | split an imported key into two arithmetic shares |
| ZCHK | poly-unit check: FAULT unless two polynomials sum to 0 mod q in every coefficient |
| SXOR, SEQ (IO_SEQ) | sponge sink that XORs output into a seed entry; the I/O-unit check that two masked seed entries are equal |
| ok, OKINI, OKCHK, OKOUT | the masked ciphertext-comparison bit; set it to 1, check its two copies agree, unmask it (tag checks only) |
| μ (mu) | Decompress_1(m), the message encoded as polynomial coefficients |
| Compress_d | ML-KEM's rounding of a coefficient to d bits |
| E_xx | a seed entry: 4 lanes of 64 bits per share (E_SK session key, E_KB the K̄ entry, E_CBD the CBD scratch) |
| KEK | key-encryption key, derived from the PUF key |
| PCT | pairwise consistency test (FIPS 140-3) |
| FO transform, implicit rejection | the re-encryption check in Decaps; a bad ciphertext yields a pseudorandom K̄ instead of an error |
| `MASKED`, `PQSE_LOWPOWER`, `LOWPOWER=1` | build options: masked datapath on or off; operand isolation on |
| `CG_SRST`, `CLOCKGATE` | power-flow options: rewrite reset-over-enable registers for gating; insert clock gates |
| SAIF | switching activity interchange format: per-net toggle counts that OpenSTA uses for power |
