# PQSE: a post-quantum secure element (`hw/se`)

A compact, low-power secure-element chip for ML-KEM-768 (FIPS 203), designed side-channel-aware from the start. It targets identity and digital-trust applications: identity cards, digital-signature tokens, payment, and IoT identity. Design priorities, in order:

1. small area;
2. very low power;
3. physical-attack resistance:
   - **first-order masking of every secret**: KeyGen, Encaps and Decaps, the key wrap, the PUF key and secure messaging, with every masked gadget checked exhaustively in the robust probing model (glitches **and** transitions);
   - **hiding** (constant time, a fresh random word order for every shuffled instruction and every NTT layer, random dummy cycles);
   - **fault detection** (duplicated decoding and comparison, control-flow and RAM checks) with a wipe-and-count response.

> **Status.** Version 1 passed all 21 checks of `make sim-se` in Verilator; version 3 ran through `make sim-se` with the fixes found there (probing check, KMAC constant, SPI read timing). **Version 4 (this one) re-architects for a contactless card (smallest area and energy, speed no longer a priority) and is desk-checked, not yet simulated**: run the checklist in section 13, starting with `make sim-se`, then `make se-gowin`. Section 5 lists what changed.

---

## 1. Block diagram

```
            SPI (4 pins) / Avalon-MM (FPGA)      tamper  IRQ   trigger (TEST only)
                       |                            |     ^     ^
              +--------v----------------------------v-----+-----+-----+
              |  pqse_host: CSRs, lifecycle TEST>PERSO>USER>KILLED,   |
              |  buffer windows, command policy, K export policy,     |
              |  fault counter, power-on / fault / tamper ZEROIZE     |
              +----------+----------------------------+---------------+
                         | command, kexp               | host <-> I/O buffer (idle only)
              +----------v------------+    +----------v---------------------------+
              | sequencer + microcode |    | I/O buffer 4 KB: own ek, PUF helper  |
              | 1024 x 96 ROM,        |    | + check value, peer ek / c in, c out,|
              | pc + ~pc shadow,      |    | K (TEST/PERSO), wrapped-key blob,    |
              | instruction parity,   |    | secure message                       |
              | engine-ran check,     |    +--------------------------------------+
              | RAM-port precharge    |
              +--+-----+-----+----+---+
                 |     |     |    |      +-------------------+  +----------------------+
   +-------------v-+ +-v-----+-+ +v-----v-+ | seed registers  |  | polynomial RAM 0     |
   | masked Keccak | | poly    | | masked  | | 2 RAMs (one per |  | even slots: share 0, |
   | state in 2    | | unit:   | | gadgets:| | share) x 64 x 65|  | public    1024 x 25  |
   | RAMs 64 x 64, | | 1 mult, | | CBD/B2A,| | + parity        |  +----------------------+
   | DOM, + sponge | | 1 BFU,  | | mu, Com-| +-----------------+  | polynomial RAM 1     |
   | + SampleNTT   | | shuffled| | press,  |                      | odd slots: share 1   |
   +-------+-------+ +----+----+ | compare,| +-----------------+  |           1024 x 25  |
           |              |      | select, | | I/O unit: encode |  +----------------------+
   +-------v--------------+--+   | 2 x ok  | | decode, seed ops,|  | SRAM-cell PUF+RM(1,5)|
   | TRNG (ring osc. + 90B   |   +---------+ | counters, SEQ    |  | code-offset extractor|
   | health tests) -> Trivium|  Fisher-Yates +-----------------+  | masked ML decoding,  |
   | PRNG 64 bit/clk (masks) |  128x7 2R1W register file          | check value + retry  |
   +-------------------------+  (pqse_perm.v)                     +----------------------+
```

## 2. How the priorities shaped the design

| Decision | Area | Power | Physical attacks |
|---|---|---|---|
| **One engine at a time** under microcode; every RAM port is a mux on the instruction class | no hazard logic, no duplicated ports | idle engines do not toggle; low peak current | one operation's leakage at a time |
| **One modular multiplier, one butterfly** for NTT, INTT and pointwise multiply; 1R1W RAMs, 2 coefficients per word | v2 of the fast core had 7–14 multipliers | — | shuffled order |
| **Lane-serial Keccak with the state in RAM** (two 64 × 64 RAMs, one per share; 64-bit datapath, 162 clocks per round) | ~770 flip-flops instead of ~5,100, no 25-way lane multiplexers | the state's 3,200 bits no longer clocked every cycle | 64 random bits per lane for DOM χ; the shares never share a RAM |
| **Microcode in a ROM** (registered read, two-clock fetch) | a ROM block instead of ~100 k gates of table logic | one ROM read per instruction | — |
| **Masking by repeating linear steps per share** (NTT, INTT, PWM on share 0, then share 1) | costs time, not area | — | first order |
| **Bit-serial masked gadgets**: CBD/B2A, Compress, compare, select | one DOM AND per gadget | — | a register stage after every DOM AND, a compress register before its result is reused |
| **Share-domain RAMs**: even slots (share 0) and odd slots (share 1) in two RAMs; seed shares in two RAMs | same bits, one extra parity bit per word | — | the shares never share a bit line, sense amplifier or output register |
| **Shuffle table in a 128 × 7 register file** (2 reads, 1 write: LUTRAM / MLAB, a small register file on a chip), inside-out Fisher–Yates, two clocks per element | ~1 k flip-flops less than a flip-flop table | — | a uniformly random order per instruction and per NTT layer |
| **Parity + control-flow redundancy**; duplication only where a fault would leak (the comparison result, the decoding of m′) | one bit per RAM word, a 10-bit pc shadow, one parity bit per instruction | — | detects the common single faults |
| **SRAM-cell PUF** (960 cross-coupled NAND pairs, one row of 32 excited per read) | 2 gates per bit (~0.01 mm² in SKY130, ~2 k LUTs on the FPGA, or ~2.9 k flip-flops and no LUTs as butterfly cells, `PQSE_PUF_BFLY`) instead of 1,920 ring oscillators | only the row being read switches | re-excitable, so majority reads work |
| Clock enables, RAM read enables (the share-1 Keccak RAM idles in unmasked jobs), operand isolation, TRNG ring oscillators only while collecting | — | yes | — |
| `MASKED = 0` reference build | removes the share-1 seed RAM and masked Keccak; masks are 0 | — | none (cost comparison and TVLA positive control) |

## 3. Speed

Speed is no longer a priority (v4): the target is a contactless card, where the 13.56 MHz field supplies a few milliwatts and the reader allows waiting-time extensions, so v4 trades clocks for area and energy. Version 1 measured (Verilator): KeyGen 108,669 clocks, Encaps 111,935, masked Decaps ~176–182 k. Version 4, measured with `make sim-se LOWPOWER=1` (hiding on; the Keccak permutation takes ~3,050 clocks, about 50 permutations per KEM operation):

| Command | Clocks (measured) | at 13.56 / 4 = 3.39 MHz (contactless) | at 10 MHz |
|---|---|---|---|
| KeyGen, masked: s / e and G computed twice + pairwise consistency test (242,129 without them) | 545,344 | 161 ms | 54.5 ms |
| KGWRAP (PUF key, KeyGen, wrap) | 587,755 | 173 ms | 58.8 ms |
| Encaps, masked | 267,964 | 79 ms | 26.8 ms |
| Decaps, masked, m′ decoded twice | 298,465–304,526 (290,116 hiding off) | 88–90 ms | 30 ms |
| UNWRAP (PUF key right at the first read; s / e computed twice, no pairwise test) | 271,738 (293,466 with the 3-read retry) | 80 ms | 27.2 ms |
| SEAL / OPEN (128 bytes, KMAC) | 22,550 | 6.7 ms | 2.3 ms |
| ENROLL | 38,876 | 11.5 ms | 3.9 ms |

The fault hardening of KeyGen (section 8) costs ~300 k clocks: the pairwise consistency test ~250 k (an Encaps and a partial Decaps), the second computation of s, e and G ~50 k. UNWRAP derives the key pair too and runs the duplicates, not the pairwise test.

What the protection costs in time: running NTT, PWM and INTT once per share; the masked compression (two clocks per adder bit, ~50 clocks per coefficient for d = 10); the second decoding of m′ (~10 k clocks); drawing a Fisher–Yates order before every shuffled instruction (128–256 clocks each, the next NTT layer's order is drawn while the current layer runs); the χ DOM AND (4 clocks per lane). A PUF read takes ~15 clocks (excite a row, let it settle, sample), so a reconstruction is ~15 k clocks, and the 3- or 5-read retry ~45 k / ~75 k.

### Power and energy (ASIC, SkyWater 130 nm)

Measured with `make se-power-vcd SKY130_LIB=<.lib> RAM_MACRO=1`: the mapped,
clock-gated netlist runs a whole masked KeyGen in Verilator, every net's
toggles go into a SAIF, OpenSTA turns them into power and
`scripts/power/pqse_energy.py` into energy (sky130_fd_sc_hd, tt, 25 C, 1.8 V;
SRAM macros from access counts with an assumed energy per access; no clock
tree, wires, pads or analog blocks). Before the low-power RTL below:

| KeyGen | v4 | v5 (serial, Tang Nano 9K) |
|---|---|---|
| Clocks | 242,129 | 944,548 |
| Time at 3.39 MHz | 71 ms | 279 ms |
| Energy (logic + SRAM) | 49.2 uJ | 59.3 uJ |
| Average power at 3.39 MHz | 0.69 mW | 0.21 mW |

After the low-power RTL, the clock gating and the fault hardening (v4, `LOWPOWER`, `CG_SRST`, KeyGen with the pairwise test and the duplicates, 99.6 % of the pins annotated):

| KeyGen | v4, now |
|---|---|
| Clocks (gate-level run) | 549,032 |
| Time at 3.39 MHz | 162 ms |
| Energy | 92.5 uJ (logic 71.0 uJ, SRAM 21.5 uJ: the Keccak and seed RAMs 19.2 uJ) |
| Energy per clock | 168.5 pJ (203 pJ before the low-power RTL) |
| Average power at 3.39 MHz | 0.57 mW |
| Flip-flops / behind a clock gate | 7,774 / 6,622 (269 gates) |
| Setup slack at 20 ns | 7.3 ns |

The flip-flops dominate: sequential internal power is 72 % of the logic power. The 1,152 flip-flops still clocked every cycle draw ~2.3 uW each at 50 MHz, ~2.7 mW together - about 40 % of the logic energy; `build/sepower/ffs_<tag>.txt` names them.

v4 is the primary design: about one contactless-card transaction slot per KEM
operation, and the lower energy per operation.

Low-power RTL (no change in function or in the masking schedule):

| Technique | Where |
|---|---|
| Idle registers cleared once on going idle (not rewritten every idle clock), so they hold and can be clock-gated | `pqse_poly`, `pqse_mcomp`, `pqse_puf`, `pqse_sponge`, `pqse_masked` (gadget registers) |
| chi DOM registers (384 flip-flops) load only while a permutation runs; the absorb-port registers only around an absorb | `pqse_keccak` |
| theta column parities in registers, accumulated by the chi write-back: the parity pass runs in round 0 only, RP reads only the 5 lanes of a column (per round 35 of 135 state-RAM reads and 36 of 162 clocks fewer; +640 flip-flops) | `pqse_keccak` |
| Operand isolation (`PQSE_LOWPOWER`, ASIC builds): the PRNG word, the TRNG word and the shared RAM read buses reach an engine only while it is busy; the shuffle multiplier sees the PRNG word only while drawing | `pqse_core`, `pqse_perm` |
| Clock gating (Yosys `clockgate`; registers with a synchronous reset over the enable are first rewritten to enable = en \| rst, `CG_SRST=1`) | `make se-power*`, `CLOCKGATE=1` |

`make se-power` also lists the flip-flops still clocked every cycle, by RTL
register (`build/sepower/ffs_<tag>.txt`), the next candidates.
`make sim-se LOWPOWER=1` simulates the operand-isolated variant.

## 4. Security design (threat → countermeasure)

| Threat | Countermeasure | Where |
|---|---|---|
| Timing attacks | Fixed schedule; no branch, address or loop count depends on a secret. Implicit rejection by a masked select. Branches only on public results (ek/dk checks, tags, the PUF check value) | `pqse_ucode.v`, `pqse_masked.v` |
| DPA/CPA on Decaps (static key, chosen ciphertexts) | ŝ held as two arithmetic shares mod q. NTT/INTT/PWM per share; masked Compress₁ → m′ as Boolean shares; masked Keccak for G, J, PRF; masked CBD (B2A); masked Compress_d with a bit-by-bit masked comparison c′ = c; masked select K′ / K̄. m′, r′, K′, K̄ and the comparison result are never unmasked | `pqse_mcomp.v`, `pqse_masked.v`, `pqse_keccak.v` |
| DPA on KeyGen, Encaps, and repeated UNWRAP | KeyGen and Encaps are masked too. TRNG seeds are conditioned by the masked sponge and come out as shares; s, e, y, e₁, e₂ come out of the masked CBD; t̂ is unmasked only when both share sums are complete; the ciphertext leaves through the masked compression | `pqse_ucode.v`, `pqse_mcomp.v` |
| Side-channel CCA attacks on decryption/re-encryption (plaintext-checking oracles; Ravi et al. 2020, Ueno et al. 2021) | No unmasked m′, no unmasked comparison bit, no early abort, no gate that ever computes ok during the comparison | as above |
| **Glitches and transitions** | Every masked gadget passes an exhaustive first-order check in the **robust probing model with glitches and transitions** (`make se-probe`, section 6). The rules it enforces: shares meet only in registered DOM cross terms; every DOM result goes through a compress register before it is used again; a value is unmasked only from two registers that nothing else loads; RAM words are read share 0 → public word → share 1 and the two RAM output registers are precharged between instructions; registers behind the read bus never hold one share while the bus carries the other | `pqse_mcomp.v`, `pqse_masked.v`, `pqse_keccak.v`, `pqse_io.v`, `pqse_sponge.v`, `pqse_core.v` |
| Single-trace / horizontal attacks on the NTT (Primas et al. 2017) | A uniformly random permutation (inside-out Fisher–Yates) for every PWM / ADD / MSPLIT / Compress / μ / CBD instruction, and its own for every NTT / INTT layer (drawn in the background while the previous layer runs); 0–15 random dummy clocks before every engine start | `pqse_perm.v`, `pqse_poly.v`, `pqse_core.v` |
| Profiled attacks on message decoding with repeated Decaps of one ciphertext (masked FPGA Kyber broken with ~400 traces + majority vote, ASHES 2023 / JCEN 2025) | m′ compression, the re-encryption compare, the ciphertext compression, μ and the CBD process their 128 words in a fresh random order per run; outputs go into registers per share domain | `pqse_mcomp.v`, `pqse_masked.v` |
| **Fault attacks** (skip the comparison, force "c′ = c", glitch the program counter, flip key bits, disturb the decoding of m′) | Two independently masked copies of the comparison result (OKCHK); **m′ decoded twice with fresh masks and a fresh order, compared share-wise (IO_SEQ)**; pc + complemented shadow; complemented shadows on the sequencer, Keccak and sponge control registers; instruction parity; engine-ran check; parity on every RAM word; a hardware PRNG freshness check; a host command watchdog; the KeyGen pairwise consistency test. Any of them aborts with result 8; the host resets the engines, wipes all keys, counts the fault; the third fault → KILLED | `pqse_core.v`, `pqse_masked.v`, `pqse_io.v`, `pqse_host.v` |
| Reading keys through the interface | No command outputs dk, ŝ, z, m′, K (in USER) or the KEK. Fixed buffer windows, nothing while a command runs. Temporaries are wiped after every command, engine registers are cleared when idle, the Keccak state is cleared between hash jobs, and a power-on wipe clears RAM contents left over from before a reset | `pqse_host.v`, `pqse_ucode.v`, all engines |
| The shared secret leaving the chip | In USER, K never leaves: it stays masked as the session key for SEAL / OPEN. Only TEST / PERSO export K (known-answer tests) | `pqse_ucode.v`, `pqse_host.v` |
| Debug features abused in the field | Injected seeds only in TEST; key import and PUF enrollment only in TEST/PERSO; raw PUF / TRNG dumps and the measurement trigger only in TEST; the lifecycle only moves forward | `pqse_host.v`, `pqse_top.v` |
| Physical tamper | Tamper input aborts the command, wipes every key, moves to KILLED. A chip ORs its sensors (clock / voltage glitch, temperature, light, an active shield) into it: those are analog cells from the PDK / an IP vendor, not RTL | `pqse_host.v` |
| Weak randomness | RO TRNG with SP 800-90B repetition-count, adaptive-proportion and startup tests; SHA3-256 conditioning; Trivium PRNG reseeded per command, never handing out a mask bit twice (checked in simulation); failure → result 5 (ZEROIZE still runs) | `pqse_rng.v` |
| Key storage without NVM | The 64-byte seed d‖z is wrapped with a KEK from the PUF: KEK = SHA3-256(k_PUF ‖ "K"); blob = nonce ‖ (d‖z ⊕ SHAKE256(KEK‖nonce)) ‖ SHA3-256(KEK‖nonce‖ct). The PUF key is decoded in masked form and checked against a 64-bit check value before use (section 7) | `pqse_puf.v`, `pqse_ucode.v` |

## 5. What changed

**Version 3 → 4: compact and low-power for a contactless card** (measured with `make se-gowin` on the Tang Nano 20K's GW2AR-18 as the area yardstick: v3 needed 44 k LUT4s, twice the device).

| # | Version 3 | Version 4 |
|---|---|---|
| 1 | Keccak state in ~5,100 flip-flops (two 1,600-bit shares, column parities, plane and operand registers) behind 25-way lane multiplexers; 86 clocks per round | **State in two 64 × 64 RAMs**, one per share (lanes, parities, the ρπ output); three passes per round (θ parities, θ+ρ+π, χ+ι), one read and one write per clock; ~770 flip-flops; 162 clocks per round. χ operands are loaded one lane each and cleared after the AND (checked by `make se-probe`, which now models this schedule) |
| 2 | Microcode table read combinationally (synthesized as logic) | **ROM with a registered read** (a ROM block on the FPGA), two-clock fetch |
| 3 | PUF: 1,920 ring oscillators (one disjoint pair per bit) | **SRAM-cell PUF**: 960 cross-coupled NAND pairs (the storage core of an SRAM cell), re-excited per read; option `PQSE_PUF_SRAM` for a real SRAM macro's power-up values (section 7) |
| 4 | — | `make se-gowin`: Yosys fit report for the Tang Nano 20K with the largest modules |
| 5 | ByteEncode / ByteDecode with 128-bit bit buffers and barrel shifters | **bit-serial** (a 64-bit lane register, one bit per clock) |
| 6 | Trivium PRNG, 64 rounds per clock | **32 rounds per clock** into a 64-bit word that is fully fresh two clocks after a take; consumers that take in consecutive clocks (B2A, SEL, the adder's AND clock, the ok copies) use only the top half, which is always fresh; a hardware check aborts the command with FAULT on any violation (`ferr`). The dummy-cycle delay is skipped while an NTT layer order is drawn in the background |
| 7 | Keccak rotation as a shift-left / shift-right pair; PUF key shares and SEL operands read by variable bit index | one barrel rotator per share; shift registers (the bit in use is always bit 0) |

**Version 2 → 3:**

| # | Version 2 | Version 3 |
|---|---|---|
| 1 | Shuffle table: 128 × 7 flip-flops (~900 FF, ~1,000 LUT); NTT layers ordered by one permutation composed with per-layer affine maps (lowest bit of the order = x₀ ⊕ k) | **128 × 7 2R1W register file** (MLAB / LUTRAM; a register file on a chip), inside-out Fisher–Yates, two clocks per element; **every NTT / INTT layer gets its own uniformly random order**, drawn in the background (double-buffered halves) |
| 2 | Masked gadgets checked only by TVLA on a register-level power model | **Exhaustive robust-probing check (glitches + transitions)** of every gadget, with negative controls (`make se-probe`). It found, and v3 fixes: the adder carry and the ok accumulators reused a DOM result without a compress register; the adder's partial products held their value after the compress clock (next to the carry share masked by the same random bit); unmasking XORs (`srd0 ^ srd1`, the ciphertext bit, `ok0 ^ ok1`, the K export) were fed by both shares all the time, so they computed m′ bits, keys and the running ok while nothing was meant to be revealed; the χ operands came from plane muxes holding both shares of every lane; the read mux could hold both shares of a coefficient |
| 3 | PUF reconstruction with single reads; a wrong key showed only as a bad blob | **64-bit key check value** in the helper data (ENROLL), **majority retry** with 3 then 5 reads per bit, result 12 if all fail |
| 4 | Decoding of m′ protected only indirectly (a wrong m′ fails the re-encryption) | **m′ decoded twice** (fresh masks, fresh order) and compared share-wise without unmasking (IO_SEQ) |
| 5 | Secure messaging: SHAKE256/SHA3 with a direction byte, fixed 128-byte messages, strict counter order | **KMAC256 / KMACXOF256** (SP 800-185, customization "E1"/"E2"/"T1"/"T2"), **lengths 1–128**, a **64-message sliding replay window** (late messages inside the window are accepted once) |
| 6 | 512-entry ROM full | **1024-entry ROM** (10-bit pc), room for the new programs |
| 7 | No measurement support | **Trigger pin** (TEST only), System Console capture script and `pqse_tvla.py board` for oscilloscope traces; `make se-power` (SKY130 power and timing) |
| 8 | RO-PUF: 32 oscillators compared in 960 overlapping pairs (the whole response carries at most log2(32!) ≈ 118 bits) | **one disjoint oscillator pair per response bit** (1,920 oscillators): independent bits, so the 128-bit target is reachable |

## 6. The masked gadgets in one page

- **Arithmetic shares mod q** (ŝ, e, y, e₁, e₂, w, u, v): x = x₀ + x₁ mod q; linear operations run per share. Share 0 lives in even slots (RAM 0), share 1 in odd slots (RAM 1).
- **Masked CBD / B2A** (`pqse_masked.v`): the masked sponge writes the PRF output (both shares, each in its own seed RAM) into the scratch entries E_CBD (12–15); M_CBD reads it one word (8 bits = 2 coefficients) at a time in the random order T[w] and turns the Boolean-shared bits into arithmetic shares, T = v·b₀ − R, A₀ = b₁ ? −T : T, A₁ = b₁ ? v − R : R, with weights +1, +1, −1, −1 (and 1665 for μ). The word writer reads share 0, a public word, share 1, and writes each share from its own write register.
- **Compress_d** (d = 1, 4, 10) of a shared coefficient (`pqse_mcomp.v`): each share scaled on its own, y_s = round(x_s · 2^K / q) mod 2^K, K = d + 14 (+2¹³ on share 0); the top d bits of the sum are exactly Compress_d(x). The sum is a bit-serial ripple-carry adder on Boolean sharings a = (y₀⊕R, R), b = (R′, y₁⊕R′), two clocks per bit: a DOM AND with four registered partial products, then the carry shares compressed into registers: carry′ = a ⊕ ((a⊕b) ∧ (a⊕c)). The partial products load every clock (0 outside the compress clock): a held cross term next to the carry share that contains its random bit would unmask it. Output modes: 0 m′ as Boolean shares into a seed entry; 1 each bit compared with the public ciphertext bit and ANDed into `ok`; 2 the ciphertext bit, unmasked from two registers only this mode loads.
- **Comparison**: `ok` is a Boolean-shared bit; **two copies** with independent randomness accumulate the same comparisons, each update a DOM AND (partial products reloaded every clock, no hold) followed by a compress clock. OKCHK unmasks only (ok_a ⊕ ok_b), which is 0 unless a fault hit one copy. OKOUT (tag checks only) copies the shares into two registers nothing else loads and combines them there.
- **Select**: K = K̄ ⊕ (ok ∧ (K′ ⊕ K̄)), one DOM AND per bit; the result stays masked in seed entry E_SK.
- **Keccak χ** (state in RAM, one RAM per share): X = ¬a[x+1], Y = a[x+2], one DOM AND per bit (64 fresh random bits per lane). Per lane: read a[x+1] → X, read a[x+2] → Y, the AND, then a[x] ⊕ products is written back. X is cleared after the AND and Y and the products load every clock, so the AND never sees both shares of one lane, not even in consecutive clocks; this makes any lane order safe (the RTL keeps 0, 2, 4, 1, 3; the check covers both orders, and the same schedule with the operands held until reloaded as a negative control).
- **IO_SEQ**: e ⊕ e₂ per share into registers, then the two differences compared: 0 unless a fault hit one decoding; nothing about m′ is ever combined.

**Robust-probing check** (`scripts/pqse_probe_verify.py`, `make se-probe`, also run by `make sim-se`): each gadget is simulated clock by clock as the RTL schedules it; a probe on any wire observes every register of its combinational cone — including a register's own value when its load is a data mux, and every input of every mux — in the probed clock and the clock before. For every probe and clock, the distribution of what it sees is computed exactly over all masks and fresh random bits and compared across all secrets. Gadgets: the Compress adder (m′ and compare modes, the latter together with the ok accumulator), the two ok copies with OKCHK, SEL, the B2A, a χ slice, IO_SEQ, and the RAM read port with the registers behind it. Negative controls (the v2 adder, ok accumulator, χ and read port, v3's χ with the natural lane order, the first v3 adder draft with held partial products, and v4's χ with held operands) must be reported as leaking, which shows the checker can see these leaks. The check is at the level of each gadget's registers and its schedule; the synthesized netlist can be checked the same way with a netlist-level tool (PROLEAD).

## 7. PUF fuzzy extractor (`pqse_puf.v`)

- **Response source: an SRAM-type PUF.** An SRAM cell's power-up value is decided by the mismatch of its two cross-coupled inverters; that is the most studied PUF in smart cards. Four builds of the same 960-bit source (`pqse_puf_raw`):
  - `PQSE_PUF_LATCH` (FPGA prototype, and the compact choice for an open-PDK chip): 960 cells, each the storage core of an SRAM cell, two cross-coupled NAND gates (`pqse_pufcell`), in 30 rows of 32. A read excites the cell's row (both nodes forced high, as an SRAM cell before power-up), releases it, lets it settle (8 clocks) and samples the cell through a synchronizer. Each read re-runs the "power-up", so the 3- and 5-read majority retries work. Cost: 2 gates per bit, ~0.01 mm² in SKY130 (an OpenRAM 1 KB macro is ~0.2 mm²), ~2 k LUTs on the FPGA.
  - `PQSE_PUF_BFLY` (FPGA prototype without spending LUTs on the PUF): the same 30 × 32 array, row excitation, settle time and synchronizer, but each cell is a **butterfly cell** (`pqse_bflycell`, Kumar et al., HOST 2008): two always-transparent latches built from the logic cells' flip-flops (Gowin `DLC` / `DLP`), each one's D fed by the other's Q, one with an asynchronous clear and one with an asynchronous preset driven by the row's excite. Excited, the pair is forced to 0/1, which a loop of two non-inverting stages cannot hold; released, it falls to 0/0 or 1/1 as the mismatch of the two paths decides, the same metastable resolution as an SRAM cell. Each cell takes the row's excite through its own flip-flop: wired straight to the shared row net, the 32 cells of a row are logically identical and GowinSynthesis merged them as equivalent registers (990 latches instead of 1,920). Cost: 2 latches + 1 flip-flop and no LUT per bit, so ~1,920 LUT4s move to ~2,880 of the GW2AR-18's 15,552 flip-flops (`make se-gowin PUF=bfly`, `make se-gowin-eda PUF=bfly`). Place both latches in one CLS (or two neighbouring ones if a CLS cannot mix a clear and a preset register) with matched D routes. Butterfly cells on FPGAs are known for strong routing bias (low inter-device distance in published Spartan-3E measurements), so measure uniformity and uniqueness with PUFRAW as for the NAND cell. On Intel parts (DE10-Nano), whose ALM registers have no latch mode, Quartus would build the latches from LUTs: keep `PQSE_PUF_LATCH` there.
  - `PQSE_PUF_SRAM` (a chip with a compact SRAM compiler): the power-up contents of a dedicated 32 × 32 SRAM that nothing writes (`pqse_puf_sram`, a black box mapped to the PDK's macro). One sample per power-up — natural for a card, which powers up at every tap — so repeated reads return the same bits and the retries add nothing; the code alone must cover the bit-error rate.
  - default: the simulation model (fixed device pattern, read noise, drift and a noisy mode).
- **Why not the FPGA's block RAM**: Gowin's BSRAM and shadow SRAM are initialized by the bitstream (zeros by default, UG285), and Gowin parts have no equivalent of the power-gating + partial-reconfiguration trick that enables block-RAM SRAM PUFs on Xilinx 7-series (Wild & Güneysu, FPL 2014). The latch cell (LUTs) or the butterfly cell (flip-flops) gives the same SRAM-cell physics in the fabric. On an FPGA the routing of the two gates dominates the mismatch, so expect more bias than on a chip: place each pair in one logic cell and measure with PUFRAW.
- **Independence**: every cell belongs to exactly one response bit. (A source that reuses its elements is weaker: 32 ring oscillators compared in 960 pairs give at most log2(32!) ≈ 118 bits in total.)
- **Code**: Reed–Muller RM(1,5) = [32, 6, 16]: 6 key bits per block of 32 response bits, minimum distance 16, corrects up to 7 errors per block. 30 blocks: 960 response bits, a 180-bit key, 960 bits (15 lanes, 120 bytes) of helper data.
- **Entropy**: the helper data leaks up to 26 bits per block, so the key keeps 30 · (32h − 26) bits for a min-entropy h per response bit: 128 bits need h ≥ 0.946. `pqse_puf_stats.py` estimates h from the bias of PUFRAW dumps; one device's 960 bits cannot prove h ≥ 0.946 at 99% confidence (that takes about 4,500 bits, i.e. 5 devices), so measure several boards / chips, and raise PUF_NB if h is lower.
- **Enroll** (TEST/PERSO): k from the TRNG (masked seed entry); each response bit read 5 times (majority: a clean reference); helper w = r ⊕ C(k), in two clocks per bit: (r ⊕ C(k₀)) is registered first, then C(k₁) is added, so no gate sees C(k₀) ⊕ C(k₁). Then the microcode stores the **check value** H(k ‖ "C") (first 8 bytes of SHA3-256, computed by the masked sponge) in the 16th helper lane.
- **Reconstruct**: one read per bit. With a fresh random 6-bit R per block the decoder sees y = r′ ⊕ w ⊕ C(R) = C(k ⊕ R) ⊕ e and decodes k ⊕ R by maximum likelihood; the key comes out as shares (k ⊕ R, R): **the unmasked key never exists in the decoder.** The 32 bits of a block are read in a random order (bit x ⊕ xm, fresh xm per block), so the read schedule does not line up across reconstructions. The microcode hashes it (masked) and compares the check value; if it does not match, it reconstructs again with the **majority of 3 reads** per bit, then of **5 reads**; if that fails too, result 12 (PUF).
- **Failure rates** (`pqse_model.py` check 7, Monte Carlo with the real decoder, printed for 5–20% bit errors per read): at 10% a single read loses the key in a large share of unwraps, the retries in none of the samples. `pqse_puf_stats.py` turns a measured bit-error rate into the same numbers.
- **Drift**: majority voting removes read noise only; a bit that flips for good fools every read, and the code corrects it. The testbench flips 9.4% of the bits permanently (unwrap still works) and adds 20% read noise (the retry recovers the key).
- **Measurement**: PUFRAW (TEST) dumps 960 single-read bits; `scripts/pqse_puf_stats.py` gives uniformity, bit-error rate, inter-device distance, failure rates with and without retries, and the entropy left after the helper data.

## 8. Fault detection and response

| Detector | Catches | Where |
|---|---|---|
| Two masked `ok` copies + OKCHK | a fault that forces "c′ = c" or skips part of the comparison (FO-transform bypass) | `pqse_masked.v` |
| m′ decoded twice + IO_SEQ | a fault in one decoding of m′ (the attacks that disturb the decoder and watch the result) | `pqse_ucode.v`, `pqse_io.v` |
| pc + ~pc shadow register | glitches of the program counter (skipped / repeated instructions) | `pqse_core.v` |
| Instruction parity (computed at fetch, checked at execute) | corrupted instruction register | `pqse_core.v` |
| Engine-ran check | an engine start that was suppressed (the engine never reported busy) | `pqse_core.v` |
| Even parity on every polynomial-RAM and seed-RAM word (seed parity checked per share) | bit flips in stored keys and intermediates | `pqse_core.v` |
| Even parity on every Keccak state word (65-bit RAM words, both shares) and on each theta column-parity register, checked on every read / use, per share | faults in the hashing of KeyGen, Encaps, KMAC and the PRF (without it they gave a wrong output silently; Decaps only had the re-encryption check) | `pqse_keccak.v` |
| Complemented shadow copies of the lifecycle, the fault counter and the tampered flag | a flipped bit in the security state (KILLED back to USER / TEST, the fault count reset): handled like the tamper input | `pqse_host.v` |
| Complemented shadow copies of the control registers: the sequencer state, the Keccak pass / round counter / column / plane / lane counters, the sponge state and return state (written in the same statements, compared every clock) | a flipped control bit: skipped Keccak rounds or passes (a weakened, wrong hash that the state parity cannot see), a sequencer stopped in idle mid-command, a jump between sponge states (in the fault campaign these gave wrong KeyGen outputs silently, or hangs) | `pqse_core.v`, `pqse_keccak.v`, `pqse_sponge.v` |
| Command watchdog in the host: a command (or the internal wipe) still running after 2²² clocks (~84 ms at 50 MHz; the longest command, KeyGen with its PCT, needs ~0.5 M) | a hang that no other detector sees (the core stopped silently, an engine or a TRNG wait that never ends): handled like a detected fault; a hung wipe → KILLED. Kept in the host because a stopped core also stops its own cycle counter; the host stays busy until then | `pqse_host.v` |
| PRNG freshness check in hardware: a random word taken before it is fully fresh again (two advances after the previous take; only a take_hi one clock after a take may use the fresh top half) | reused mask bits (a fault on the PRNG's freshness counter, a skipped wait): the masking would be weakened with no visible error | `pqse_rng.v` |
| KeyGen pairwise consistency test (FIPS 140-3): before the key is marked valid, a masked Encaps of a fresh random m to the new ek (read back from the buffer, with its own H(ek)), then a Decaps of that ciphertext with the new s^ and h; K and K' compared share-wise (IO_SEQ). Its ciphertext stays in the output window (public: its K never leaves the chip) | a fault that made ek and dk disagree (a corrupted t, s or H(ek)): such a key would be published and fail every later Decaps. It cannot see a fault that changes the key pair consistently: that is the next row | `pqse_ucode.v` (608) |
| KeyGen duplicate computation: every secret polynomial (s₀..s₂, e₀..e₂) is produced twice - PRF, masked CBD, NTT - the second copy with fresh masks and its own word orders; the two NTT-domain results are compared share-wise: SUB per share (share 0 in RAM 0, share 1 in RAM 1), then ZCHK (new `pqse_poly` op: FAULT unless the two differences sum to 0 mod q for every coefficient; equal copies leave (r, −r), r a difference of fresh masks, so nothing about the polynomial is combined). G(d ‖ 3) is run twice too (XORed into its output, which must be 0, IO_SEQ against a zero entry); ρ in the buffer compared with G's. Every key derivation (KEYGEN, KGWRAP, UNWRAP); ~+70 k clocks | a fault in G, a PRF, the masked CBD or an NTT of s / e: these change ek and dk consistently, so the pairwise test passes them - a coefficient off by a few, a polynomial forced to zero (a weak key), two secret polynomials made equal (PRF nonce / domain faults, a known key-recovery attack on ML-KEM KeyGen); with KGWRAP, a published ek that a later UNWRAP of d would not reproduce. What follows the comparison is covered by the pairwise test and the RAM parity: a fault in the PWM, unmasking or encoding of t̂, or in the stored ŝ, is an NTT-domain change, i.e. a dense, large error in the time domain, and the test's decoding fails | `pqse_ucode.v` (720), `pqse_poly.v` |
| Persistent security state (`pqse_nvm`: lifecycle, fault count, tampered; set-only thermometer bits, two OR-combined copies), loaded at reset; a fault, kill or tamper event is programmed before the next command is accepted (write-ahead); a store ahead of the registers is handled like the tamper input | resetting the three-strike counter or KILLED by a reset / power cycle; rolling the lifecycle back | `pqse_host.v` |

Response: the command ends with result 8 (FAULT); the host resets every engine, runs ZEROIZE, increments the fault counter (STATUS[18:17]); the third fault moves the lifecycle to KILLED. The keys must be unwrapped or re-imported afterwards. Faults whose effect is only a wrong value inside the masked re-encryption end as an implicit rejection (a random-looking K̄), and the kill after three detected faults bounds what statistical fault attacks can collect.

## 9. Session key and secure messaging

ENCAPS (initiator) and DECAPS (responder) keep the shared secret K, masked, as the **session key** SK (seed entry E_SK; STATUS[16] = loaded). In TEST/PERSO they also copy K to the buffer for known-answer tests; in USER K never leaves.

| Command | Buffer in | Buffer out |
|---|---|---|
| SEAL | message M at `B_SM_MSG`, its length L (1–128) in header lane 1 | header H (32 B) = counter (8 B LE) ‖ L (8 B LE) ‖ 16 zero bytes; C = (M[0..L−1] ⊕ KMACXOF256(SK, H, 1024, "E"d)) ‖ zero bytes; T = KMAC256(SK, H ‖ C, 256, "T"d). Result 1 if L is not 1–128 (no counter used) |
| OPEN | H ‖ C ‖ T | M (bytes from L on are 0); result 11 (REPLAY) for a counter already accepted or more than 63 behind the newest; result 9 (BADTAG) for a bad length or tag, C left encrypted |

d = "1" for initiator → responder and "2" for responder → initiator, so a message reflected back to its sender fails. The keystream and tag come from the masked sponge (KMAC with the masked SK as the key); only C (or M) and T are unmasked, from registers that only the keystream sink loads.

**Replay protection.** Each side keeps the counter of its next sent message, and a 64-message window of accepted counters: the newest accepted counter and one bit per each of the 63 before it. A new session key resets both. SEAL counts up *before* computing the keystream, so a counter is never used twice even if the command is aborted. OPEN rejects a counter that was already accepted or is older than the window (result 11), then checks the length and the tag, and only for an authentic message marks the counter, so a forgery cannot burn a counter. Lost messages and reordering inside the window are fine; replays are not. `scripts/pqse_sm_check.py` recomputes C and T for every sealed message with its own KMAC (checked against hashlib's SHA3/SHAKE and the NIST SP 800-185 examples).

## 10. Interface

**Registers** (32-bit words, `pqse_host.v`):

| Address | Register | |
|---|---|---|
| `0x400` | ID | "PQSE" = `0x50515345` |
| `0x401` | VERSION | `0x00040000` |
| `0x402` | CTRL | [7:0] command, [8] injected seeds (TEST only); starts the command |
| `0x403` | STATUS | [0] busy, [1] done (write 1 to clear), [2] key loaded, [3] TRNG ok, [4] TRNG failed, [5] tampered, [7:6] lifecycle, [15:8] result, [16] session key loaded, [18:17] faults detected |
| `0x404` | CYCLES | clocks of the last command |
| `0x405` | LIFECYCLE | write a later state to move forward (0 TEST → 1 PERSO → 2 USER → 3 KILLED) |
| `0x406` | CONFIG | [0] hiding on (default 1) |

After reset the device is busy for ~3 k clocks (power-on wipe); wait for STATUS[0] = 0.

**Pins**: SPI (4), IRQ, tamper in, **trig** out: high during the masked comparison window (OKINI to OKCHK: in DECAPS everything secret, in OPEN / UNWRAP the tag check), in lifecycle TEST only (0 otherwise, so a deployed device gives no timing reference). On the DE10-Nano: GPIO_0[0] and LED1.

**Buffer** (words `0x000–0x3FF`, word w = half w&1 of lane w>>1):

| Lanes | Name | Host access |
|---|---|---|
| 0–147 | own ek | R; W in TEST/PERSO |
| 148–163 | PUF helper (120 B) + key check value (8 B) | R W |
| 164–311 | peer ek / ciphertext / ŝ bytes in | W |
| 312–447 | ciphertext out, raw dumps | R |
| 448–451 | K | R in TEST/PERSO |
| 452–467 | injected d (TEST), z, m (TEST), H(ek) | W in TEST/PERSO |
| 468–481 | wrapped-key blob (112 B): nonce 2 \| ct 8 \| tag 4 | R W |
| 484–507 | secure message (192 B): header 4 (counter, length, 0, 0) \| M or C 16 \| T 4 | R W |

**Commands** (CTRL[7:0]):

| # | Command | Inputs | Outputs | Lifecycle |
|---|---|---|---|---|
| 1 | KEYGEN | (TEST: d, z) | own ek | any but KILLED |
| 2 | ENCAPS | peer ek (+ TEST: m) | c (+ K in TEST/PERSO); session key (initiator) | any but KILLED |
| 3 | DECAPS | c | (K in TEST/PERSO); session key (responder) | any but KILLED, needs a key |
| 4 | IMPORT | ŝ bytes, ek, H(ek), z | — | TEST, PERSO |
| 5 | ENROLL | — | PUF helper + check value (128 B) | TEST, PERSO |
| 6 | KGWRAP | PUF helper | own ek, blob (112 B) | any but KILLED |
| 7 | UNWRAP | blob, helper | own ek (regenerated) | any but KILLED |
| 8 | ZEROIZE | — | — | any but KILLED |
| 9 | SEAL | message, length | H, C, T | any but KILLED, needs a session key |
| 10 | OPEN | H, C, T | message | any but KILLED, needs a session key |
| 11 | PUFRAW | — | 960 PUF bits (lanes 312–326) | TEST |
| 12 | TRNGRAW | — | 136 TRNG words (lanes 312–447) | TEST |

**Result codes** (STATUS[15:8]): 0 OK, 1 bad input (ek modulus / dk hash check / message length), 2 denied (lifecycle), 3 no key, 4 bad blob, 5 TRNG failure, 6 unknown command, 7 KILLED, 8 FAULT, 9 bad tag or length (OPEN), 10 no session key, 11 replay (OPEN), 12 PUF key not reconstructed.

**SPI** (mode 0, SCK ≤ clk/4): write `02 aH aL` then 4 bytes per word, least significant byte first; read `03 aH aL xx` then 4 bytes per word.

## 11. Files

| File | Contents |
|---|---|
| `pqse_top.v` | `pqse_top` (chip: SPI, IRQ, tamper, trigger), `pqse_avalon` (FPGA), `pqse_sys` |
| `pqse_host.v` | CSRs, lifecycle, access windows, command and K-export policy, fault counter, power-on / fault / tamper ZEROIZE |
| `pqse_spi.v` | SPI slave |
| `pqse_core.v` | sequencer (10-bit pc) with fault detection and RAM-port precharge, share-domain RAMs with parity, TRNG/PRNG, measurement trigger, port multiplexing |
| `pqse_ucode.v` | microcode: masked KeyGen / Encaps / Decaps, Import, Enroll, PUF key + retries, Wrap / Unwrap, SEAL / OPEN, raw dumps, Zeroize |
| `pqse_keccak.v` | masked lane-serial Keccak-f[1600], state in two RAMs (one per share) |
| `pqse_sponge.v` | sponge controller: sources, padding, KMAC, sinks (incl. the message keystream) |
| `pqse_sample.v` | SampleNTT (and the unmasked CBD sampler, not instantiated) |
| `pqse_poly.v` | NTT/INTT/PWM/ADD/SUB/MSPLIT/ZERO/ZCHK with shuffling, per-layer orders |
| `pqse_perm.v` | Fisher–Yates permutation in a 128 × 7 register file |
| `pqse_io.v` | encode/decode, seed-register ops (incl. SEQ), message header, length and replay window, raw TRNG dump |
| `pqse_mcomp.v` | masked Compress_d: m′, compare, ciphertext output |
| `pqse_masked.v` | masked CBD (B2A), μ, select, two ok accumulators, tag check |
| `pqse_puf.v` | SRAM-cell PUF (cross-coupled NAND pairs) or SRAM-macro PUF (+ simulation model with noise, drift and a noisy mode), RM(1,5) fuzzy extractor with masked decoding, raw dump |
| `pqse_rng.v` | ring-oscillator TRNG + health tests, Trivium PRNG |
| `pqse_arith.v`, `pqse_mem.v`, `pqse_defs.vh`, `pqse_func.vh` | arithmetic, RAMs, constants |
| `pqse_avalon_hw.tcl` | Platform Designer component |
| `../sim/tb_pqse.sv` | functional testbench (15 groups) |
| `../sim/tb_pqse_tvla.sv`, `../../scripts/pqse_tvla.py` | TVLA testbench, ciphertext generator (Python ML-KEM, self-checked), report, and the board mode for oscilloscope traces |
| `../../scripts/pqse_probe_verify.py` | exhaustive robust-probing check of the masked gadgets |
| `../../scripts/pqse_model.py` | gadget, fuzzy-extractor, retry and shuffle math |
| `../../scripts/pqse_sm_check.py` | independent KMAC check of the sealed messages |
| `../../scripts/pqse_puf_stats.py` | PUF / TRNG statistics, failure rates from a measured bit-error rate |
| `../../scripts/pqse_power.tcl` | OpenSTA power / timing script (`make se-power`, `make se-power-vcd`) |
| `../../scripts/pqse_lib2v.py`, `../sim/tb_pqse_gate.sv` | cell models from the Liberty file (incl. clock gates) and the pin-level testbench of the gate-level power run |
| `../../scripts/power/` | SRAM macro wrapper, Liberty stubs and counting models (`RAM_MACRO=1`), energy per command (`pqse_energy.py`) |
| `../../scripts/pqse_fit.py` | Tang Nano 20K fit report from Yosys `synth_gowin` (`make se-gowin`), with the largest modules |
| `../../quartus/jtag/de10_nano_pqse.v`, `pqse_test.tcl`, `pqse_tvla_capture.tcl` | DE10-Nano top (KEY1 = tamper, GPIO_0[0] = trigger), System Console demo + raw dumps, TVLA capture runs |

## 12. Commands

```bash
make sim-se                      # model + probing checks, RTL testbench, KMAC check, PUF/TRNG stats
make sim-se TRACE=1              # + every microcode instruction
make se-probe                    # the robust-probing check alone (--full: larger widths)
make sim-se-tvla MASKED=1 N=200  # TVLA of the masked Decaps on a power model (expect: no leak)
make sim-se-tvla MASKED=0 N=200  # positive control (expect: leaks)
make sim-se-fault FN=200          # fault-injection campaign (Decaps; FOP=keygen): expect no SILENT outcome
make se-area                     # Yosys gate count; SKY130_LIB=<.lib> for SkyWater 130 nm
make se-power SKY130_LIB=<.lib>  # SKY130 power (vectorless, ACT=0.1) and the slowest path; RAM_MACRO=1: logic only
make se-power-vcd SKY130_LIB=<.lib> RAM_MACRO=1   # energy per KeyGen from a gate-level run (whole command, SAIF; GL_CMD=2: Encaps)
make se-power-sample SKY130_LIB=<.lib> RAM_MACRO=1 GL_FMT=vcd GL_CLOCKS=<n>   # the same from 8 sampled 2000-clock windows (fast with VCD; GL_PAR, GL_THREADS for speed)
make se-gowin                    # fit on the Tang Nano 20K (GW2AR-18), largest modules; PUF=0: without the PUF cells, PUF=bfly: butterfly cells
make se-gowin-eda                # the same with Gowin EDA (gw_sh: GowinSynthesis, area goal, + place & route): the real fit
cd quartus/jtag && quartus_sh -t build.tcl se    # DE10-Nano, then source pqse_test.tcl
```

**The testbench** (`tb_pqse.sv`) checks: the NIST KeyGen / Encaps known answers through the masked datapath; masked Decaps (valid and implicit rejection) on imported NIST keys, hiding on and off, one trigger pulse; a round trip; the ek / dk input checks; PUF enroll with check value, wrap / zeroize / unwrap, unwrap after 9.4% drift, a 20%-noise PUF recovered by the retry, a wrong check value (result 12), blob rejection; SEAL / OPEN between the two roles with lengths 128 / 100 / 1, bad lengths, out-of-order delivery inside the window, replays, a counter too old for the window, modified ciphertext / length / padding, reflection, no session key after ZEROIZE; raw PUF / TRNG dumps; injected faults (pc shadow, an ok copy, a double-bit error in m′ that only the second decoding catches, RAM parity after a power cycle, a Keccak state bit and a theta column-parity bit mid-permutation, the Keccak round counter, the sponge state, the sequencer state, a hung command caught by the watchdog, a stale PRNG word, a dk corrupted after ek was computed and caught by the pairwise consistency test, a parity-blind Keccak fault in G(d ‖ 3) caught by the recompute check, a small change of one coefficient of s₀ after the sampler caught by the duplicate compare) with wipe, count and KILLED; every KeyGen runs the pairwise consistency test; a flipped lifecycle bit (shadow mismatch → KILLED, tampered); persistence: KILLED, the fault count and tampered survive a power cycle, and a lifecycle register rolled back below the store is caught; the USER rules (no trigger, no K); SPI and tamper.

**Fault campaign** (`tb_pqse_fault.sv`, `scripts/pqse_fault_report.py`): every run a new chip (persistent store cleared) from a power cycle, one bit flipped in one of 38 targets (program counter and shadow, instruction register, engine state machines, the PRNG freshness counter, the lifecycle, the fault counter, the persistent store, Keccak control / datapath / column parities / state RAMs, the masked comparison copies and gadget registers, the compression, poly and I/O registers, the polynomial and seed RAMs, both shares) at a random clock of a NIST-vector Decaps or KeyGen. Outcomes: unchanged, detected (FAULT: wiped, counted), implicit rejection (Decaps returned K′ = J(z‖c): harmless), SILENT (a wrong output with result 0 - what fault attacks exploit), hang (past the host watchdog, which the campaign shortens to 2²¹ clocks: a hang means the watchdog failed). Single-bit flips in registers the RTL does not check (e.g. a Decaps datapath register whose effect the re-encryption check absorbs) can still be SILENT: the report names them.

**TVLA** (`tb_pqse_tvla.sv`): fixed-vs-random m with random coins (only Decaps' secret intermediates differ between the classes), hiding off, lifecycle USER. Power model: per clock, the number of toggling bits in the RAM buses and the datapath, gadget, unmasking and Keccak registers. Welch t per clock; |t| > 4.5 marks a candidate leak, reported by microcode address, with the chance level and TVLA's two-run confirmation (`pqse_tvla.py confirm`).

**On the board** (`quartus/jtag/pqse_tvla_capture.tcl`): `pqse_tvla.py gen` makes the ciphertext set; the script imports the NIST key and runs one Decaps per ciphertext with the trigger on GPIO_0[0]; an oscilloscope in segmented mode records one trace per run (EM probe over the FPGA or a shunt in the core supply); `pqse_tvla.py board traces.npy tvla_in.txt` computes t per sample (`--align` for jitter or hiding on), and `confirm` applies the two-set rule.

## 13. Verification you run (in this order)

1. `make sim-se` — Python model and probing checks, then the RTL testbench: `TEST PASSED`, `SM CHECK PASSED`, `PROBING CHECK PASSED`, `MODEL CHECKS PASSED`.
2. `make sim-se-tvla MASKED=1 N=200`, then with `SEED=2` and `pqse_tvla.py confirm`; `MASKED=0` must show leaks.
3. `make se-gowin` (must say "fits"), `make se-area` and `make se-power SKY130_LIB=...` (MASKED=1 and 0) for the cost table of the proposal; `make se-power-vcd SKY130_LIB=... RAM_MACRO=1` for the energy per command (Verilator 5.036+ for SAIF; `pqse_energy.py` explains the SRAM energy assumptions).
4. On the DE10-Nano: `build.tcl se`, `pqse_test.tcl` (all PASS), PUFRAW / TRNGRAW dumps through `pqse_puf_stats.py` on several boards, then a board TVLA with `pqse_tvla_capture.tcl`.
5. Optional, for a tape-out: a netlist-level probing check of the synthesized gadgets (PROLEAD).

**When `make sim-se` fails** (bring-up order):
1. **Compile errors**: `build/sesim/build.log`.
2. **`pqse_model.py` / `pqse_probe_verify.py` fail**: the gadget in the named file must match its model (the probing check prints the probe and clock).
3. **Stuck busy after reset**: the power-on ZEROIZE (`TRACE=1` shows pc 560–602).
4. **FAULT (result 8) where none was injected**: `TRACE=1` prints which detector fired (ctl / engine / parity / keccak / okchk / decoder / prng / zchk). Decoder: the two CMPR1 runs disagree (check the share-wise SEQ and that both CMPR1 read the same ACC slots); in KeyGen at pc 733 / 744 / 755 / 766 / 777 / 788 the compare of the two copies of s₀..e₂ (zchk), at 790–791 the recompute check of G, at pc 698 the pairwise consistency test (K ≠ K': check the PCT's Encaps / Decaps against the plain ones at 192 / 320). Keccak: a parity or a control-shadow mismatch (a register assigned without its shadow). prng: a consumer took a word less than two advances after the previous take.
5. **KeyGen ek wrong**: first the Keccak alone (`TRACE=1`: the first HASH is H(ek); a wrong SHA3 points at `pqse_keccak.v`: the pass transitions TH → RP → CHI, the `pdst` / `rho` tables, the χ write-back one clock after the AND, ι on lane 0), then the sponge's read latency (`H_SKX`, `H_STRV`), the masked CBD into two slots, `padd` of the t̂ shares, NTT → INTT round trip, PWM.
6. **Encaps wrong, KeyGen right**: the compression output mode (`so0`/`so1` → WL/WH bit position, lane count) or the XOF byte order (ρ‖i‖j).
7. **Decaps wrong**: run with `MASKED=0`; if that passes, the bug is in a gadget (B2A weights, `neg1`, reader bit order, the ok compress clock).
8. **SEAL / OPEN**: `pqse_sm_check.py` names the wrong part (header, ciphertext, tag); its self-test checks the KMAC itself first. A KMAC mismatch: the constant lanes `KM_A0` / `KM_PRE` / customization in `pqse_sponge.v`.
9. **UNWRAP result 12**: the check value lane (helper lane 15 = lane 163) or `h_kchk`; result 4: the tag.
10. **Hangs** (TIMEOUT): `TRACE=1` shows the last instruction: a stream sink that never reports done, or the sponge waiting for TRNG words.

## 14. Scope

**Security level and model.** First-order masking (one probe), shown at the level of each gadget's registers and schedule in the robust probing model with glitches and transitions, plus hiding against higher-order and horizontal attacks. The register-level TVLA and the gadget-level probing check do not see what synthesis does to the netlist, or coupling inside an SRAM macro; the board TVLA and the optional netlist check cover that. The FPGA's latch PUF and ring-oscillator TRNG are demonstrators of the interfaces and the post-processing (FPGA routing makes the latch cells more biased than on silicon); a chip uses characterized cells or macros. The lifecycle, fault counter and tampered flag are kept in a persistent store (`pqse_nvm`: set-only bits, two OR-combined copies); its behavioural model survives a reset but, on the FPGA, not a power-off (a Gowin GW1NR / GW2AR could use its user flash); a chip replaces the module with its OTP / eFuse macro wrapper, same ports.

**Design alternatives** (other valid choices, not missing pieces):
- **Higher-order masking** (d ≥ 2) of the Decaps path: the gadgets generalize (DOM with d + 1 shares, more random bits, ~3–4× area and time); this design keeps first order plus hiding, the usual trade-off for smart-card-class area and power.
- **Ascon-AEAD128** (SP 800-232) instead of KMAC for secure messaging: smaller and faster per message, but a second permutation to mask; KMAC reuses the masked Keccak that ML-KEM needs anyway.

**Possible extensions** (new features, not part of this design):
- **ML-DSA** (FIPS 204) signatures on the same Keccak and polynomial datapath, for identity-document signing.
