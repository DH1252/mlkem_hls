# Hand-written RTL core for ML-KEM-768 (`hw/manual`)

This folder holds a second implementation of the accelerator. It is written directly in Verilog instead of being generated from C by Bambu. From the bus it looks the same as the Bambu core: same ports, same registers, same mailbox layout. The testbench, the System Console script and the ARM program therefore work with either core without changes.

> **Status: first version, not yet simulated or synthesized.** Every file was written and checked by reading only. Treat it as a design you still have to bring up, not as a working core. The Bambu core (`hw/bambu`, `quartus/ip/mlkem_accel`) remains the verified reference. Section 6 gives a debug plan.

| | Bambu core (verified) | This core (estimated) |
|---|---|---|
| KeyGen | 141,790 cycles | about 5,900 cycles |
| Encaps | 167,298 cycles | about 6,900 cycles |
| Decaps | 221,888 cycles | about 9,300 cycles |
| at 50 MHz | 2.8 / 3.3 / 4.4 ms | 118 / 138 / 186 µs |

The estimates come from stepping through the microcode schedule by hand (section 5), with an expected error of about ±10%. The Bambu figures were measured in co-simulation. The main reasons for the difference of about 24× are listed in section 2.5.

Only ML-KEM-768 (k = 3) is supported. The PARAMS register always reads 3.

---

## 1. Files and how to use them

| File | Contents |
|---|---|
| `mlkem_rtl.v` | Top level `mlkem_rtl`: Avalon-MM registers (copied from `hw/rtl/mlkem_avalon.v`), the 8 KB mailbox as four byte-wide dual-port RAMs, and the core |
| `mlkem_rtl_core.v` | Sequencer, the microcode ROM with the KeyGen, Encaps and Decaps programs, and the wiring of the engines |
| `mlkem_rtl_hash.v` | Keccak engine: one round per clock, the sponge controller, and the SamplePolyCBD and SampleNTT samplers |
| `mlkem_rtl_arith.v` | Modular multiplier, butterfly unit, base-case multiplier, and the polynomial ALU (NTT, INTT, pointwise multiply, add, subtract) |
| `mlkem_rtl_io.v` | IO engine: ByteDecode/ByteEncode with built-in (de)compression, word copies, compare, constant-time select |
| `mlkem_rtl_mem.v` | Polynomial memory (12 slots), seed registers, the mailbox read stream |
| `mlkem_rtl_hw.tcl` | Platform Designer component `mlkem_rtl` (same interfaces as `mlkem_accel`) |

**Simulate** (Linux/WSL, Verilator 5, the same setup as `make sim-rtl`):

```bash
make sim-manual            # same testbench and NIST vectors as the Bambu core
make sim-manual TRACE=1    # also prints every instruction the sequencer issues
```

The testbench picks its device under test with the macro `MLKEM_DUT`: `mlkem_avalon` by default, `mlkem_rtl` for this core. The output is in `build/mansim/sim.log`, and Verilator's messages are in `build/mansim/build.log`.

**Build for the board**, only once the simulation passes:

```bash
cd quartus/jtag
quartus_sh -t build.tcl rtl          # stand-alone JTAG design with this core
```

Then program the board and run `mlkem_test.tcl` exactly as in the main guide, section 10. For the ARM path (GHRD), copy this folder to `ip/mlkem_rtl` in the GHRD project, set `CORE` to `mlkem_rtl` in `quartus/ghrd/add_mlkem_to_ghrd.tcl`, and follow the main guide, section 11.

---

## 2. How it works

```
            start, op --> +---------------------------------+ --> done, result
                          |  sequencer + microcode ROM      |
                          +----+-----------+-----------+----+
                        HASH   |      ALU  |       IO  |
                               v           v           v
 mailbox port B <-- +------------+ +------------+ +--------------+ <--> mailbox port A
 (Keccak reads)     | Keccak     | | NTT  INTT  | | ByteDecode   | ---> mailbox port B
                    | sponge +   | | PWM  ADD   | | ByteEncode   |      (second copies)
                    | CBD /      | | SUB        | | (de)compress |
                    | SampleNTT  | |            | | copy, compare|
                    +--+------+--+ +-----+------+ +--+--------+--+
                       |      |          |           |        |
                       |   +--+----------+-----------+--+     |
                       |   | polynomial memory S0 - S11 |     |
                       |   +----------------------------+     |
                       +------ seed registers E0 - E5 ---------+
```

### 2.1 Sequencer and microcode

ML-KEM is a fixed sequence of large steps: hash a seed, sample a polynomial, NTT, multiply, encode. The sequencer walks through a program of such steps and issues one instruction per clock, in order.

- An engine instruction (HASH, ALU or IO) waits until that engine is idle. The engine then works for hundreds of cycles while the sequencer moves on and can start the other engines.
- `WAIT` waits until the named engines are idle.
- `BR` jumps if the BAD flag is set, which happens when an input check fails.
- `END` waits for all engines, then reports the status.

This is where the speed comes from: the three engines work at the same time. For example, the Keccak engine samples the next matrix entry while the ALU multiplies the current one.

The programs are in `mlkem_rtl_core.v`, in the functions `prog_kg`, `prog_en`, `prog_de` and `reenc`. `reenc` is K-PKE.Encrypt, which Encaps and the re-encryption step of Decaps share. The instruction format is described at the top of that file. The ROM is addressed with the next program counter and its output is registered, so Quartus can place it in block RAM.

The microcode, not the hardware, keeps the engines from getting in each other's way. The rules are:

1. **One engine per polynomial slot at a time.** The memory gives each slot's read port to one reader, in the priority order ALU-C, ALU-A, ALU-B, IO. If two engines touched one slot, one of them would silently read the wrong address.
2. **Mailbox port B** belongs to the Keccak engine while it reads mailbox words. The IO engine uses port B for writes only (the second copy in ENC/S2M, and M2M), and never at the same time.
3. **Seed registers:** an entry is not read while another engine writes it.
4. **Flags:** a `BR` comes after a `WAIT` for the IO step that sets BAD.

If you change a program, check these four rules for every step.

### 2.2 Keccak engine (`mlkem_rtl_hash.v`)

- The 1600-bit state computes one Keccak-f round per clock, so a permutation takes 24 clocks.
- The engine absorbs up to two parts and then a suffix of up to 2 bytes. Each part comes either from the mailbox, one 64-bit lane per 2 clocks through 32-bit port B, or from a seed register, one lane per clock. The engine then pads and squeezes.
- The permutation is lazy: it runs only when a full block has to be absorbed or more output is needed.
- Output goes to one of three places:
  - the seed registers, for H, G and J;
  - **SamplePolyCBD_2**, which writes two coefficient pairs per clock;
  - **SampleNTT**, which takes 3 bytes per clock and writes each accepted pair of coefficients.

  The two samplers write straight into a polynomial slot.

| Function | Instruction | Cycles (about) |
|---|---|---|
| G = SHA3-512 (seed, 33 or 64 bytes) | `U_SHA3_512` | 45 |
| H = SHA3-256 (ek, 1184 bytes from the mailbox) | `U_SHA3_256` | 520 |
| J = SHAKE256 (z‖c, 1120 bytes from the mailbox) | `U_SHAKE_J` | 500 |
| PRF + SamplePolyCBD_2 (one polynomial) | `U_CBD` | 100 |
| XOF + SampleNTT (one matrix entry) | `U_XOF` | 230 to 330, depends on rejections |

### 2.3 Polynomial ALU (`mlkem_rtl_arith.v`)

Coefficients are always stored fully reduced (0 to q−1). A 24-bit memory word holds two neighbouring coefficients: word w = {coefficient 2w+1, coefficient 2w}.

- **Memory layout.** Each slot has two banks. Word w lives in bank parity(w) at address w[6:1].
  - The two words of every NTT butterfly (w and w + 2^p) differ in one bit, so they are always in different banks.
  - Both banks can therefore be read and written in the same clock: 2 words, which is 4 coefficients, or 2 butterflies per clock.
- **NTT / INTT**, about 500 cycles.
  - 7 layers × (64 issue clocks + 7 clocks to drain the pipeline).
  - The INTT halves every butterfly output (x/2 mod q is a shift, plus q when x is odd). Over 7 layers this gives the 1/128 factor, so no scaling pass is needed.
- **PWM**, about 140 cycles: the FIPS 203 base-case multiply, one coefficient pair per clock, with optional accumulation into the result slot.
- **ADD / SUB**, about 67 cycles: 4 coefficients per clock.
- **Modular multiplication** uses Barrett reduction with 5039 = ⌊2²⁴/q⌋, the same formula as `mod_q()` in `src/poly.c`, which `test/test_unit.c` checks exhaustively.

### 2.4 IO engine (`mlkem_rtl_io.v`)

| Op | What it does |
|---|---|
| DEC | ByteDecode_d from the mailbox or a seed register, 2 coefficients per clock. For d = 12 it reduces mod q and can flag values ≥ q (the ek modulus check). For d < 12 it can apply Decompress_d |
| ENC | Optional Compress_d, computed as ⌊((x << d) + 1664) · 2580335 / 2³³⌋, which is exact for every input here. Then ByteEncode_d to the mailbox, to two mailbox places at once (ek is written into both ek and dk), to a seed register (m′), or compared with the mailbox (c = c′ ?) |
| S2M, M2S, M2M | Copy 32-byte values between the seed registers and the mailbox |
| CMP | Compare a seed register with the mailbox (the dk hash check) |
| SEL | Write K′ or K̄ to the mailbox depending on the compare result, in constant time |
| ZERO | Clear the shared-secret field after a failed dk check |

### 2.5 Why it is so much faster than the Bambu core

- **Word-wide data paths.** Keccak moves 64-bit lanes instead of bytes. The NTT does 2 butterflies per clock, and encoding handles 2 coefficients per clock.
- **Everything pipelined.** Each engine accepts new data every clock instead of taking several states per loop iteration.
- **Three engines in parallel** under the sequencer, instead of one sequential controller.
- **No copying.** Operands stay in the polynomial memory and the seed registers. The Bambu core copies every input and output byte between the mailbox and its internal arrays.

### 2.6 Memories

| Memory | Size | What is in it |
|---|---|---|
| Polynomial memory | 12 slots × 2 banks × 64 words × 24 bit (24 small RAMs) | ŝ, ê/t̂, ŷ, u, v, matrix entries |
| Seed registers | 6 × 32 bytes (flip-flops) | E0 K / K′, E1 σ / r / r′, E2 H(ek), E3 m′, E4 K̄, E5 ρ |
| Mailbox | 2048 × 32 bit (4 byte-wide dual-port RAMs) | inputs and outputs, `src/mlkem_accel.h` |
| Microcode ROM | 384 × 80 bit | the three programs |

Slot use:

| Slots | KeyGen | Encaps, and the re-encryption in Decaps | Decaps, decryption part |
|---|---|---|---|
| S0–S2 | ŝ₀..ŝ₂ | ŷ₀..ŷ₂ | – |
| S3, S4 | matrix entries, used alternately | matrix entries; at the end μ (S3) and v (S4) | u′₀ and u′₂ (NTT) in S3, ŝ₀ and ŝ₂ in S4 |
| S5, S6 | ê₀, ê₁, which become t̂₀, t̂₁ | u₀, u₁ | S5 accumulates ŝᵀ∘û′; S6 holds v′, then w |
| S7 | ê₂, which becomes t̂₂ | t̂₀ | t̂₀, decoded for the re-encryption |
| S8, S9 | – | t̂₁, t̂₂ | t̂₁, t̂₂ |
| S10 | – | u₂ | u′₁ (NTT) |
| S11 | – | e₁ᵢ, then e₂ | ŝ₁ |

---

## 3. The programs in short

**KeyGen**
1. (ρ, σ) = G(d‖3). ρ goes into ek and into the copy of ek inside dk; z goes into dk.
2. Sample s₀..s₂ and e₀..e₂ with CBD and transform each with an NTT. While the NTTs run, the finished ŝᵢ are encoded into dk.
3. Compute t̂ row by row: t̂ᵢ = êᵢ + Σⱼ Â[i][j]∘ŝⱼ. Each Â[i][j] = SampleNTT(ρ‖j‖i) is sampled into S3 or S4 while the ALU multiplies the previous entry.
4. Encode each t̂ᵢ into ek and dk at the same time.
5. Compute H(ek) and store it in dk.

**Encaps**
1. Compute H(ek) while the IO engine decodes t̂. The decode doubles as the modulus check: a bad ek ends with RESULT 1 and nothing written.
2. (K, r) = G(m‖H(ek)).
3. Run K-PKE.Encrypt:
   - ŷ = NTT(CBD);
   - uᵢ = INTT(Σⱼ Â[j][i]∘ŷⱼ) + e₁ᵢ, compressed and encoded as each one finishes;
   - v = INTT(t̂ᵀ∘ŷ) + e₂ + Decompress₁(m).

**Decaps**
1. Compute H(ek) for the hash check while u′ and ŝ are decoded and the products are accumulated.
2. Compare the hash. A mismatch zeroes K and ends with RESULT 1.
3. w = v′ − INTT(ŝᵀ∘NTT(u′)), then m′ = Encode₁(Compress₁(w)).
4. (K′, r′) = G(m′‖h). Meanwhile K̄ = J(z‖c) has been computed.
5. Re-encrypt, comparing each part of c′ with c as it is produced.
6. K = (c = c′) ? K′ : K̄, chosen in constant time.

---

## 4. Constant time

The schedule does not depend on secret data. SampleNTT's running time depends on ρ, which is public. CBD, NTT, the encoders, the compare and the final select all take a fixed number of cycles. The only branches are the input checks, which depend on public inputs (ek, and dk's stored hash). A mismatch between c and c′ changes only which seed register SEL copies, not the timing. This covers timing only; power and EM side channels are not addressed.

---

## 5. Where the cycles go (estimate)

These numbers come from stepping through the schedule with the per-engine figures from section 2.

- **KeyGen, about 5,900 cycles.**
  - G, 50 cycles, then the first CBD, 100.
  - 6 NTTs back to back on the ALU, 3,000. The other CBDs overlap with them.
  - 9 matrix entries, about 250 each, 2,250. Each overlaps with the previous PWM, which is shorter, so this phase is limited by the Keccak engine.
  - The last PWM and ENC, 280.
  - H(ek), 520.
- **Encaps, about 6,900 cycles.**
  - H(ek), 520, with the decoding overlapped. Then G.
  - 3 NTTs, 1,500.
  - Three u rows at about 1,300 each: three matrix entries each, again Keccak-bound, plus an INTT of 500.
  - v, about 1,200: 3 PWMs, an INTT, 2 ADDs, ENC.
- **Decaps, about 9,300 cycles.** The decryption takes about 2,950 cycles; the re-encryption adds the Encaps figure minus H(ek) and G.

The busiest engine is the ALU, with about 5,500 cycles of work in Encaps. A perfect overlap would give about 6,300 cycles for Encaps, so the schedule is within about 10% of what this set of engines allows.

**Comparison with published designs** (cycles; different FPGAs and clock rates):

| Design | KeyGen | Encaps | Decaps | Notes |
|---|---|---|---|---|
| Bambu HLS core (this project) | 141,790 | 167,298 | 221,888 | measured in co-simulation, 50 MHz target |
| This core | ~5,900 | ~6,900 | ~9,300 | estimated; Fmax not known yet |
| Xing & Li, TCHES 2021 (Kyber-768) | 6,316 | 7,925 | 10,049 | published, 161 MHz |
| Ni et al., ACM TECS 2025 (ML-KEM-768) | 3.3K | 4.2K | 5.4K | published, 270 MHz, 4 butterfly units, 10,781 LUTs |

**Size.** It has not been synthesized, so this is only a guess. Expect about 5,000 to 9,000 ALMs:

- the Keccak round and state (1600 flip-flops) are the largest part;
- the ALU and the IO engine next;
- then the seed registers and the read multiplexers.

Also expect roughly 15 to 25 DSP blocks for the 7 modular multipliers and the compress multipliers, and about 35 M10K blocks or MLABs: 24 small polynomial RAMs, 8 for the mailbox, and a few for the microcode if Quartus puts it in block RAM. The DE10-Nano has 41,509 ALMs, 112 DSP blocks and 553 M10K blocks.

---

## 6. Bringing it up

Work in this order. The testbench runs every check even after one fails, so read the whole log each time.

1. **Compile.** Run `make sim-manual`. If it fails, `build/mansim/build.log` has Verilator's errors. Expect a few typos or width mismatches in a first version.
2. **Hangs.** If the simulation prints `TIMEOUT`, run `make sim-manual TRACE=1` and look at the last instructions. An engine that never goes idle stalls the sequencer at the next instruction for that engine, at a `WAIT`, or at `END`. The busy logic is at the end of each engine module. Another thing to check is an engine waiting for input that never comes: the mailbox read stream (`mlkem_rd_stream`) or a sampler's `in_ready`.
3. **Wrong KeyGen output.** Compare the output in the order it is produced. Byte ranges are offsets within ek or dk:

   | Output | Bytes | Produced by |
   |---|---|---|
   | ρ in ek | 1152–1183 | G, S2M |
   | z in dk | 2368–2399 | M2M |
   | ŝ₀ in dk | 0–383 | CBD, NTT, ENC |
   | t̂₀ in ek | 0–383 | SampleNTT, PWM |
   | H(ek) in dk | 2336–2367 | SHA3-256 over the mailbox |

   To see intermediate values, print them from the C model (`src/mlkem.c`, compiled with `make test`) and compare with the hardware state. Reach that state with hierarchical references in the testbench, for example:
   - `dut.u_core.u_seed.g_ent[5].r` is ρ;
   - `dut.u_core.u_pmem.g_slot[3].g_bank[0].u_ram.mem[i]` is a slot word.

   Remember the bank rule: word w is in bank parity(w) at address w[6:1].
4. **Encaps**, then **Decaps** with a valid ciphertext, then with a modified one (implicit rejection), in the order the testbench runs them.
5. **Unit tests worth writing** if a block misbehaves:
   - the Keccak engine against SHA3-256 and SHAKE128 test vectors;
   - the ALU NTT against `poly_ntt()`;
   - IO DEC then ENC of the same data (a round trip).

   Each is a small testbench around one module.

**Weak spots to look at first:**
- the hash engine's handshake between the mailbox read stream and the absorb logic, including the switch from part 1 to part 2;
- the SampleNTT byte buffer;
- the IO bit packer and unpacker for d = 10 and d = 4;
- the NTT address and zeta-index arithmetic;
- the one-clock timing of the registered flags (BAD, DIFF) against `WAIT` and `BR`.

---

## 7. Making it faster later

In order of payoff per effort:

1. **Sample matrix entries earlier.** In Encaps the rows of Â are limited by the Keccak engine: an entry takes about 250 cycles, a PWM 140. Sampling entries into free slots during the NTT and INTT phases, when the Keccak engine is mostly idle, saves about 500 to 1,000 cycles. This is a microcode change only.
2. **A wider SampleNTT parser.** Taking 6 bytes per clock instead of 3 cuts an entry to about 160 cycles.
3. **4 butterflies per clock** (4 banks), as in Ni et al. This brings an NTT to about 250 cycles.
4. **64-bit mailbox reads for the Keccak engine**, using both ports or a wider mailbox. This makes the absorb part of H(ek) and J twice as fast.
5. **Fuse steps.** CBD output could go straight into the NTT, and the ADD after an INTT could be folded into its last layer.
6. **Clock.** After the first Quartus run, check Fmax. The Keccak round is one clock of XOR logic and should run well above 50 MHz. If needed, split long paths (the SampleNTT buffer shifter, the IO unpacker) with a register stage.
