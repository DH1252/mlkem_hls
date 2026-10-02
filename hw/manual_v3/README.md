# Hand-written ML-KEM-768 core, v3: parallel engines (`hw/manual_v3`)

The third version of the hand-written core. Its goal is fewer clock cycles than the fastest published FPGA design (HPKA, IEEE TC 2023) while keeping v2's low-power style. From the bus it is the same as the other cores: same ports, registers and mailbox layout. The testbench, `mlkem_test.tcl` and `mlkem_hps` work unchanged.

> **Status: first version, not yet simulated or synthesized.** v2 (`hw/manual_v2`) passes the NIST-vector simulation and is the baseline. v3 was written from v2 and reviewed by reading only (a separate review found no certain bug).

| Clock cycles (ML-KEM-768) | KeyGen | Encaps | Decaps | Source |
|---|---|---|---|---|
| v2 (`hw/manual_v2`) | 2,867 | 3,375 | 4,737 | simulated |
| **v3 (this folder)** | **~1,390** | **~1,430** | **~2,070** | estimated from the schedule |
| HPKA (fastest FPGA design found) | 1,700 | 2,400 | 3,000 | published |
| Kim, TCAS-II 2024 | 2,600 | 2,700 | 4,100 | published |

In real time the Cyclone V clock still decides. v2 closes timing at 53.5 MHz (worst corner). Every v3 datapath starts at a register (see section 3), so v3 should reach a higher Fmax; that needs a PLL to use (section 6).

---

## 1. Where v2 spent its time, and what v3 changes

Counting the busy clocks per engine in the v2 schedule showed two limits:
- the **ALU** (NTT, INTT, pointwise multiply, add) was busy 80–87% of every operation, one job at a time;
- the **Keccak engine** was busy about 1,750 clocks in KeyGen alone, more than HPKA's whole KeyGen.

| Change | Effect | Idea from |
|---|---|---|
| **The ALU is split into an NTT engine and a pointwise engine** that run at the same time | NTTs overlap with multiplies and adds | HPKA's separate NTT and PWM modules |
| **8-butterfly NTT, two layers per pass** (radix-4). Four words from the four banks per clock go through two butterfly stages | NTT/INTT 273 → ~141 clocks, with the same 4 RAM banks | radix-4 / multi-layer NTT designs (Ni 2025, Jung 2025 mixed radix) |
| **New bank mapping** {odd-bit parity, even-bit parity} | Radix-4 groups, aligned groups and word pairs are all conflict-free | |
| **Passes chain without draining** | The group order in each pass is chosen so the next pass never reads a word before it is written (worst slack 17 of 19 clocks). A simulation checker proves it on every run | |
| **4 base-case multipliers** | Pointwise multiply 75 → ~44 clocks | |
| **Fused add after NTT too** (v2: only after INTT) | KeyGen: t̂₂ = NTT(e₂) + Σ A₂ⱼ∘ŝⱼ in one pass | |
| **Keccak block buffer** | Next block loads while permuting; next permutation runs while the sampler reads. Matrix entry ~130 → ~64 clocks, H(ek) ~260 → ~180 | HPKA's input/output stages |
| **SampleNTT 12 bytes/clock**, 3 pipeline stages | Matches one SHAKE128 block (14 × 12 bytes) per 12-clock permutation | |
| **CBD 4 bytes/clock** from the buffer | ~52 clocks per noise polynomial | |
| **IO: decode 2 words/clock; encode 2 words/clock when d ≤ 8** | Decaps starts with seven decodes on its critical path: ~945 → ~590 clocks | |
| **Region-based mailbox hazards** (seeds / ek / dk / ciphertext) and port-B tracking | KeyGen encodes ŝ₂ into dk while H(ek) reads ek | |
| **Rescheduled microcode**: matrix buffers reused as accumulators (in-place products); Decaps samples the re-encryption's first matrix column while it decodes | | list scheduling |

## 2. Low power

v3 keeps every v2 technique: valid-gated clock enables on all pipelines, RAM read enables per bank, per-engine instruction registers, operand isolation, fused operations, race to idle, `KECCAK_RPC = 1`. It adds:
- **Compact metadata pipelines.** The NTT engine carries 7 bits per pipeline stage (pass, group) and recomputes addresses and zetas where they are needed. It does not shift ~60 bits of addresses along 12 stages.
- **Idle stage 2 during the single-layer pass.** A delay line that loads only for those items carries the data instead.
- **The fused operand is read only for the last pass's write-back.**
- **Mux-based sampler input.** The sampler reads 12-byte chunks from the Keccak buffer through a mux. It does not shift the 1,344-bit buffer every clock.
- **A finished SampleNTT stops the speculative permutation at once.**
- **`POLY_RAMSTYLE = 1`** puts the 48 tiny polynomial RAMs (32 × 24 bits each) into MLABs instead of M10K blocks. That frees 48 M10Ks and usually costs less power per access. Compare both with the Power Analyzer.
- **Fewer clocks per operation**, so the static power (414 mW on this chip) costs about half as much energy per operation as in v2.

## 3. Timing (Fmax) design

The v2 Quartus reports showed RAM → logic → RAM paths and RAM → adder chains. In v3:
- every engine registers RAM data right after the slot mux (`cq`, `aq`, `bq`, `eq_w*`, `q2_old*`) before any arithmetic;
- the fused add at write-back starts from registers;
- the sampler is pipelined (split/compare, compact, stage);
- the sequencer's hazard masks are computed from the ROM output and registered with the instruction.

The longest paths left are probably the two Keccak rounds per clock (`KECCAK_RPC = 1` halves them) and the sequencer loop: masks → hazard → next pc → ROM.

## 4. Files and how to run

| File | Contents |
|---|---|
| `mlkem_rtl3.v` | top level `mlkem_rtl3`, CSRs, 2-bank mailbox |
| `mlkem3_core.v` | sequencer with hazard checking (4 engines), engine wiring, trace |
| `mlkem3_ucode.v` | microcode ROM (KeyGen 42, Encaps 50, Decaps 68 instructions) |
| `mlkem3_ntt.v` | NTT engine: radix-4, 8 butterflies, no-drain passes, fused add/sub |
| `mlkem3_pwm.v` | pointwise engine: 4 base-case multipliers, ADD/SUB |
| `mlkem3_hash.v` | Keccak engine with the block buffer |
| `mlkem3_sample.v` | SampleNTT (12 B/clock) and CBD (4 B/clock) |
| `mlkem3_io.v` | encode/decode engine (2 words/clock paths) |
| `mlkem3_mem.v` | 4-bank polynomial memory (7 roles), seed registers, read stream |
| `mlkem3_arith.v` | modular multiplier, butterfly, base-case multiplier (as v2) |
| `mlkem_rtl3_hw.tcl` | Platform Designer component `mlkem_rtl3` |

```bash
make sim-v3              # testbench + NIST vectors (Verilator 5); includes the NTT order checker
make sim-v3 TRACE=1      # + every issued instruction and each engine's busy clocks
cd quartus/jtag && quartus_sh -t build.tcl rtl3      # board build, after the simulation passes
```
Questa GUI: `do questa_v3.do` in `hw/sim` (waves of the sequencer, the four engines and the NTT passes).

GHRD: copy this folder to `ip/mlkem_rtl3` and set `CORE` to `mlkem_rtl3` in `quartus/ghrd/add_mlkem_to_ghrd.tcl`.

## 5. Bringing it up

Run `make sim-v3 TRACE=1` first. If it fails:
1. **"NTT CHECK FAIL"**: the no-drain pass order is broken, for example because a pipeline stage was added. Set `PASS_GAP` in `mlkem3_ntt.v` to the number of clocks by which the pipeline grew.
2. **KeyGen wrong, hang, or TIMEOUT.** Look at the trace for the last instruction issued; a stuck hazard shows up as `pc` not moving. Most likely places:
   - the Keccak engine's squeeze/copy hand-off (`mlkem3_hash.v`);
   - the parse sampler, which must make exactly 32 group writes.
3. **NTT results wrong.** Test the NTT engine alone: run NTT then INTT on one polynomial. The seven halvings make INTT(NTT(x)) = x. Check first:
   - the pairing and output order in stages 1 and 2 (`y*`, `zw`);
   - `zidx`;
   - the single-layer delay line.
4. **Encaps/Decaps wrong but KeyGen right.** Compare with v2's program structure. The data flow is the same; only the slots and the order changed.
5. **Everything right but more cycles than estimated.** Use the trace's busy clocks per engine to see which engine limits, and reorder the microcode. Any order that is correct as a sequential program stays correct.

## 6. Next steps

1. **A PLL.** v3's cycle counts are only worth their full value above 50 MHz. After synthesis, add a PLL in the Platform Designer system for about 90% of the reported worst-corner Fmax, and add `derive_pll_clocks` to the `.sdc`.
2. **ENC at 2 words/clock for d = 10, 12**, with a credit counter so output stays ≤ 32 bits/clock. This shortens the three t̂ encodes at the end of KeyGen by ~115 clocks, and the ciphertext encodes.
3. **Overlap Keccak jobs.** A CBD's absorb and permutation can run while the previous job's output drains (short inputs can be absorbed straight into the state): ~19 clocks per job, ~110–130 per operation.
4. **Stream H(ek) behind the t̂ encodes** (finer mailbox regions), the way HPKA streams data between modules.
