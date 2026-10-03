# PQSE secure element v1.6

v1.6 is v1.5 (`hw/se_v1_5`) with a different priority order: **energy per command and speed first, area last.** On this chip most of the energy of a command scales with the number of clocks it takes: every clock pays for the sequencer, the clock tree, the clock gates and the RAM accesses. So v1.6 spends gates and flip-flops where they remove the most clocks.

Registers, commands, key sizes, the buffer map and the microcode are the same as in v1.5. Only `VERSION` changes, to `0x00010600`. `hw/se_v1_5/README.md` describes everything not covered here, and `hw/se/README.md` the masking, fault detection and PUF.

**Status.** The RTL is written and elaborates without errors in slang. It has not been simulated. `make sim-se-v1.6` runs the v1.5 functional tests (ML-KEM-768 vectors) with the Keccak fault-injection tests moved to the new state registers.

## What changed

| Block | v1.5 | v1.6 | Where the clocks went |
|---|---|---|---|
| Keccak state | two 64 x 65 RAMs, one lane per clock | 2 x 1600 flip-flops, one per share | 40 to 60 % of every command |
| Masked permutation | 126 clocks per round, ~3,050 | 7 clocks per round, 168 | |
| Unmasked permutation (matrix A, H(ek)) | 62 clocks per round, ~1,510 | 1 clock per round, 24 | |
| Masked-mode randomness | Trivium, 32 bits per clock | plus `pqse_kprng`: 5 Trivium instances, 320 fresh bits per take | |
| Masked Compress | one coefficient at a time, ~4K + 13 clocks per word | both coefficients of a word side by side, ~2K + 8 clocks per word | 28 to 31 % of Decaps |
| ByteDecode / ByteEncode | bit-serial, (d + 1) x 256 clocks per polynomial | one coefficient per clock, ~260 clocks | 8 % of Decaps |

The NTT, PWM, masked CBD, Fisher–Yates shuffling and the PUF are unchanged.

### Keccak in flip-flops (`pqse_keccak.v`)

A **masked round** takes 7 clocks:

1. **L (1 clock).** θ, ρ and π on each share separately (`pqse_klin`, linear), written back into the state registers. The B lanes have to be registered before χ: θ mixes many lanes into each B lane, so an AND fed straight from the linear layer could see both shares of one lane.
2. **χ (6 clocks).** A whole plane per clock: five DOM ANDs, one per lane, with 64 fresh random bits each (320 per clock). The products are registered. In the same clock, the plane before is written back: `B ⊕ D00 ⊕ D01` on share 0 and `B ⊕ D11 ⊕ D10` on share 1, with ι on lane 0. The sixth clock writes plane 4.

An **unmasked round** (`msk = 0`: the XOF of A and H(ek)) is one clock: `S0 ← ι(χ(L(S0)))`. Share 1 stays zero and is not clocked.

Why the masked version stays first-order secure, with glitches and transitions:

- The two shares meet only in the registered DOM cross terms. L, the plane multiplexers, absorb, read-out and parity are all built per share.
- The AND of lane x takes column x + 1 of one share and column x + 2 of the other. The plane multiplexer can glitch to another plane but never to another column, so no AND gate sees both shares of one lane. Distinct B lanes are distinct outputs of an invertible linear map, so their share-1 parts are jointly uniform. A written-back lane is refreshed by its own random word.
- Each product holds its value for one clock and is zero outside χ.
- Operand isolation keeps the large networks still when they are not needed, which saves power and narrows what a probe can see:
  - the AND inputs are zero outside the five AND clocks;
  - the linear layer's inputs are zero outside its clock;
  - the unmasked χ's inputs are zero outside unmasked rounds.

`scripts/pqse_probe_verify.py` still models v4's RAM schedule. This argument has not been machine-checked yet (see "Not done yet").

**Fault detection.** Every lane of each share has a parity bit, loaded with the parity of whatever is written into the lane. Every clock, each stored lane is checked against its bit, per share, registered separately. A flipped state bit raises a fault in the next clock, also mid-permutation. This replaces v4's RAM-word and column parities. State, round and plane counters have complemented shadows.

The sponge interface is unchanged, so `pqse_sponge.v` only gets the wider random word. A wipe now takes one clock instead of 64.

### Wide randomness (`pqse_rng.v`, `pqse_core.v`)

`pqse_kprng` has five Trivium instances at 64 rounds per clock. They share the main PRNG's key, each with its own IV, are reseeded with it at the start of every command (18 clocks), and give 320 fresh bits on every take.

A take that hands out the same first word as the previous take means an advance was skipped, for example by a fault. That raises a fault (`kr_ferr`), like the main PRNG's stale-word check.

The masked Keccak and the Compress engine take from it. Everything else still uses the main PRNG.

### Two-coefficient masked Compress (`pqse_mcomp.v`)

The two coefficients of a polynomial-RAM word go through two bit-serial adders side by side. They share the word's reads and writes, so a word takes about 2K + 8 clocks instead of 4K + 13. The scaling uses four multipliers instead of two. The refresh takes 96 bits and each AND clock takes 2.

In comparison mode (DECAPS re-encryption), each AND clock gives two comparison bits, but the ok accumulators take one bit per two clocks. So Compress first ANDs the two bits together with one more DOM AND, in three registered stages, and passes the result on. Registers and randomness are separated by share as in v4. The extra AND costs one random bit and three clocks of latency at the end of the instruction.

### One coefficient per clock in ByteDecode / ByteEncode (`pqse_io.v`)

- **Decode.** Buffer lanes go into a 128-bit bit buffer. Each clock takes the low d bits as one coefficient. A new lane is read whenever at most 64 bits will be left, so the buffer neither runs dry nor overflows for any d up to 12.
- **Encode.** Coefficients are packed into the same kind of buffer. Every 64 bits go out as a lane. Polynomial words are read one ahead.

A polynomial takes about 260 clocks for any d. These units only handle public data, so masking does not apply.

## Estimated cycles

The figures come from the same cost model as v1.5, calibrated on v4's measured ML-KEM-768 clocks, with v1.6's per-operation costs. In the model a masked permutation costs about 200 clocks, including its share of absorbing and squeezing. A matrix entry costs about 280 clocks, limited by SampleNTT's 3 bytes per clock. These are estimates; the CYCLES register gives the real numbers in simulation.

| Command | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| KeyGen with fault checks and PCT | ~135 k (v1.5 ~315 k) | ~185 k (~420 k) | ~250 k (~595 k) |
| Encaps | ~62 k (~145 k) | ~87 k (~210 k) | ~117 k (~290 k) |
| Decaps | ~80 k (~185 k) | ~107 k (~255 k) | ~139 k (~345 k) |
| UNWRAP | ~72 k (~175 k) | ~93 k (~210 k) | ~124 k (~295 k) |

That is 2.3 to 2.5 times fewer clocks than v1.5, and about 3 times fewer than v4 for ML-KEM-768.

**One card tap at 3.39 MHz:** UNWRAP + DECAPS + SEAL, the same assumptions as in the v1.5 README.

| | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| UNWRAP + DECAPS on the chip | 45 ms | 59 ms | 78 ms |
| Whole tap, radio at 424 kbit/s | ~80 ms | ~105 ms | ~135 ms |
| Whole tap, radio at 106 kbit/s, ciphertext received during UNWRAP | ~115 ms | ~155 ms | ~210 ms |

At 106 kbit/s the radio now takes longer than the chip. Alternatively, the same tap time as v1.5 can be reached with the chip clocked about 2.4 times slower, which lowers the average power by the same factor.

What is left in Decaps (ML-KEM-768): masked Compress ~40 k, NTT and INTT ~18 k, PWM ~16 k, masked CBD ~9 k, Fisher–Yates draws ~8 k, Keccak ~7 k. The next steps toward fewer clocks would be NTT and PWM on both shares at once (2 butterflies, one per share RAM) and four Compress adders instead of two.

## Area, energy and power

Area grows, by design:

- **Keccak:** the 3,200 state flip-flops, 1,280 product flip-flops, the read registers and the parity bits replace the two Keccak RAMs and v1.5's 1,100-odd χ and θ registers.
- **PRNG:** `pqse_kprng` adds about 1,800 flip-flops.

Altogether, roughly 5,500 more flip-flops than v1.5, plus the two linear layers and the unmasked χ (about 10,000 XOR and AND gates). That puts the chip at roughly 13,000 to 14,000 flip-flops, against v4's 7,775. These are estimates; `make se-area-v1.6` gives the counts.

Energy per command should fall:

1. **Fewer clocks.** Every command takes 2.3 to 2.5 times fewer clocks, and v4's per-clock overhead (134 to 164 pJ per clock in the SkyWater 130 nm run) is paid for each one.
2. **No Keccak-state SRAM.** In v4's KeyGen the Keccak and seed RAMs used about 19 µJ of 73.5 µJ. The Keccak state no longer touches an SRAM.
3. **Quieter logic.** The large XOR networks are isolated outside their clocks, and the state lanes are clock-gated per lane: each lane has its own enable and is written only when it changes.

Peak power rises: a masked χ clock writes a plane, loads 1,280 product bits and advances five Trivium instances. That clock's current against the contactless field is the number to check first.

None of this is measured. The `se-power*` targets still build `hw/se`; they need `SE_DIR` support before v1.6 can be measured.

## Make targets

```
make sim-se-v1.6       # functional tests, ML-KEM-768 vectors (hw/sim/tb_pqse_v16.sv)
make se-area-v1.6      # Yosys cell count (SKY130_LIB=... for sky130)
make se-gowin-v1.6     # fit on the Tang Nano 20K (likely too large now: area was not a goal)
```

## Not done yet

1. Everything in the v1.5 list: ML-KEM-512 and -1024 vectors, the TVLA, fault-campaign and gate-level testbenches, and the power flow.
2. **Probing check of the new gadgets** in `scripts/pqse_probe_verify.py`: the plane-parallel masked χ (multiplexer glitches across planes, product timing) and the two-adder Compress with its comparison AND.
3. **Fault-campaign targets** for the new registers: the state lanes and their parity bits, the products, `pqse_kprng`, and the Compress comparison stages.
4. **Gowin fit.** The flip-flop state and the five Trivium instances probably do not fit the GW2AR-18 next to the rest. An FPGA build may need `MASKED=0` or a larger device.
