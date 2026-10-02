# Hand-written ML-KEM-768 core, v2: faster and lower power (`hw/manual_v2`)

This is the second version of the hand-written core. It applies the techniques of the fastest published ML-KEM/Kyber designs, together with standard low-power RTL techniques. From the bus it is the same as the other two cores (same ports, registers and mailbox layout), so the testbench, `mlkem_test.tcl` and `mlkem_hps` work unchanged.

> **Status: first version, not yet simulated or synthesized.** Like v1 (`hw/manual`), it was written and checked by reading only. Bring up v1 first if you want the simpler design to debug; v2 has more parallel machinery.

| Cycles | KeyGen | Encaps | Decaps | Source |
|---|---|---|---|---|
| Bambu HLS core | 141,790 | 167,298 | 221,888 | measured (co-simulation) |
| v1 hand-written (`hw/manual`) | ~5,900 | ~6,900 | ~9,300 | estimated |
| **v2 (this folder)** | **~2,850** | **~3,350** | **~4,700** | simulated before the timing fixes: 2,867 / 3,375; now about 2% more (ALU input registers) |
| HPKA, IEEE TC 2023 (fastest FPGA design found) | 1,700 | 2,400 | 3,000 | published |

At 50 MHz, v2 would take about 57 / 67 / 94 µs. Fmax is not known yet. The longest paths are probably the two Keccak rounds per clock and the sampler's byte buffer, so expect roughly 60–100 MHz on the DE10-Nano's Cyclone V.

---

## 1. What changed, and where the ideas come from

| Change | Effect | Taken from |
|---|---|---|
| **4 butterflies per clock.** 4-bank polynomial memory with a conflict-free mapping (word w in bank {w[0], parity(w)}, address w[6:2]) | NTT/INTT 500 → ~280 cycles | Ni et al. 2025 (4 BFUs), conflict-free mapping as in Jung et al. 2025 |
| **2 base-case multipliers** | pointwise multiply 140 → ~76 cycles | parallel multipliers as in Dang et al. and HPKA |
| **Hazard checking in hardware.** The sequencer holds an instruction only while it would clash with a job still running on another engine (slots, seed registers, mailbox) | engines overlap as much as the program order allows; no hand-placed WAITs, which removes the most error-prone part of v1's microcode | dynamic scheduling, Zhao et al. 2022 (they report about 20% fewer cycles) |
| **List-scheduled microcode.** Matrix entries are sampled into spare slots while the ALU runs NTTs | the ALU is almost never waiting for the Keccak engine | HPKA's inter-module pipelining |
| **Keccak: 2 rounds per clock** (parameter `KECCAK_RPC`) | permutation 24 → 12 cycles | round unrolling, as in the high-speed designs |
| **64-bit mailbox lane reads** (even/odd word banks) | H(ek) and J(z‖c) absorb twice as fast; H(ek) is on the critical path of KeyGen and Encaps | Bisheh-Niasar et al. (hide Keccak input time) |
| **SampleNTT: 6 bytes per clock**, results collected into aligned 4-word writes | a matrix entry ~250 → ~130 cycles | Nguyen et al. 2025 (sampling fused with hashing, no output buffer) |
| **CBD: 4 words per clock** | ~100 → ~55 cycles | – |
| **Fused operations:** INTT + add (u = INTT(·) + e₁, v = INTT(·) + e₂ + μ), INTT + reverse subtract (w = v′ − INTT(·)), decode + accumulate (e₂ + μ built by the IO engine) | removes every separate ADD/SUB pass and its RAM traffic | Nguyen et al. 2025 (overwrite intermediate data, fewer memory passes) |

What v2 still does not do, compared with HPKA: it stores whole polynomials between steps instead of streaming coefficients through FIFOs, and it runs one ALU operation at a time. Section 6 lists the next steps.

## 2. Low-power techniques

For an FPGA, dynamic power comes from switching (toggle rate × capacitance) and from clocking. The design reduces both.

1. **Clock enables on every datapath register.** Each arithmetic unit carries a valid bit with its data, and each pipeline stage loads only when that bit is set (`mlkem2_arith.v`: `mulred`, `bfu`, `basemul`; the ALU metadata pipeline; the IO pipelines; the sampler buffers; the seed registers). Idle units don't switch at all. Quartus maps these enables onto LAB clock enables, which also cuts clock-tree power inside those LABs. For an ASIC, the same enables let the synthesis tool insert clock-gating cells automatically (see below).
2. **Operand isolation for the multipliers.** Because of 1, the inputs of the DSP multipliers only change when there is real work: no toggling through the DSP blocks while waiting. In NTT mode the INTT-only registers stay still, and vice versa.
3. **RAM read enables.** Every polynomial RAM bank, every mailbox port and the Avalon side are read only in clocks that need the data. Block RAM reads cost power on every enabled clock, and v1 read all RAMs on every clock.
   - The pointwise multiply does not read the result slot when it isn't accumulating.
   - The IO engine reads one bank per word.
4. **Per-engine instruction registers.** An engine's command inputs change only when it gets a new job, so the decode logic inside the engines stays quiet.
5. **Fewer memory passes.** The fused operations (section 1) remove the separate add and subtract passes: less energy, not just fewer cycles.
6. **Race to idle.** The core finishes about 2× sooner than v1 and about 50× sooner than the Bambu core. Energy per operation falls with the time for which the clock tree and static power are spent.
7. **`KECCAK_RPC = 1`** (in Platform Designer or the `mlkem_rtl2` parameter) halves the combinational depth of the Keccak logic. That means less glitching and lower peak power, at the cost of about 10–15% more cycles. Use it when peak current or a low-power build matters more than latency.

**Measuring it.** In Quartus, run the Power Analyzer with switching activity from simulation (a `.vcd` from ModelSim/Questa, or from Verilator with `--trace` and a `$dumpvars` in the testbench). The default vectorless estimate assumes a 12.5% toggle rate everywhere, which hides exactly the gains above.

**Further FPGA option (not in the RTL).** Gate the whole core's clock between operations with an Intel clock control block (IP Catalog → ALTCLKCTRL, with its `ena` input driven by `busy_r | start`). Use the dedicated clock block only, never a LUT or logic gate on a clock.

**ASIC notes.** The RTL is written in an ASIC-friendly way: enables, synchronous resets only on control registers, no latches, no vendor primitives.
- **Clock gating:** Design Compiler `compile_ultra -gate_clock` (or Genus `set_db lp_insert_clock_gating true`) turns the register enables into integrated clock-gating cells.
- **Operand isolation:** `set_operand_isolation_style` / `set_operand_isolation_slack` in DC.
- **Multi-Vt:** high-Vt cells off the critical paths.
- **Memories:** use SRAM macros with read-enable pins for the polynomial banks and the mailbox.
- **Power gating:** the Keccak engine (the largest block) could be power-gated between operations. It holds no state across operations.

## 3. Architecture details

**Polynomial memory** (`mlkem2_mem.v`): 12 slots × 4 banks × 32 words × 24 bits. Word w = {coefficient 2w+1, coefficient 2w} lives in bank {w[0], ^w} at address w[6:2]. This keeps two access patterns conflict-free:
- the four words an NTT step touches (w, w⊕2^p, w⊕2^q, w⊕2^p⊕2^q, with q = 0, or q = 1 when p = 0);
- an aligned group 4a..4a+3.

**Sequencer and hazard check** (`mlkem2_core.v`): instructions issue in order. At issue, the slot, seed and mailbox masks of the instruction are stored with the engine that runs it. A new instruction must have masks disjoint from all running jobs:
- no shared polynomial slot (this also keeps one reader per slot's RAM port);
- no shared seed register;
- no Keccak mailbox read while an IO mailbox write is running, or the other way round.

Because issue is in order, this covers every true dependency and every conflict. BR waits for the IO engine (it sets BAD); SEL runs after all compare ENCs because the IO engine is in order.

**Instruction format:** as v1, plus ALU [21:20] fuse (1: c = INTT(c) + a, 2: c = a − INTT(c)) and IO [51] acc (DEC adds into the slot). WAIT still exists but the programs don't need it.

**Programs** (`mlkem2_ucode.v`): KeyGen 42 instructions, Encaps 50, Decaps 68. The last 30 instructions of Encaps and Decaps are one shared K-PKE.Encrypt tail; in Decaps, c′ is compared with c instead of written. Each instruction that samples into a buffer is placed right after the ALU instruction whose issue proves the buffer's previous reader has finished. The hazard check would enforce that anyway, but this placement avoids stalling the in-order stream.

**Mailbox** (`mlkem_rtl2.v`): even and odd word banks (8 RAMs of 1024 × 8, the same M10K count as before). Port A carries 32-bit words (bus or IO). Port B carries a 64-bit lane read (Keccak) or a 32-bit write (IO second copy); the hazard check keeps these apart.

## 4. Files and how to run

| File | Contents |
|---|---|
| `mlkem_rtl2.v` | top level `mlkem_rtl2`, CSRs, 2-bank mailbox |
| `mlkem2_core.v` | sequencer with hazard checking, engine wiring |
| `mlkem2_ucode.v` | microcode ROM (KeyGen, Encaps, Decaps) |
| `mlkem2_hash.v` | Keccak engine (KR rounds/clock) |
| `mlkem2_sample.v` | SampleNTT (6 B/clock) and CBD (4 words/clock) |
| `mlkem2_alu.v` | 4-butterfly NTT/INTT (with fusion), 2-way PWM, ADD/SUB |
| `mlkem2_arith.v` | valid-gated modular multiplier, butterfly, base-case multiplier |
| `mlkem2_io.v` | encode/decode engine (with accumulate) |
| `mlkem2_mem.v` | 4-bank polynomial memory, seed registers, read stream |
| `mlkem_rtl2_hw.tcl` | Platform Designer component `mlkem_rtl2` |

```bash
make sim-v2              # testbench + NIST vectors on this core (Verilator 5)
make sim-v2 TRACE=1      # also print every issued instruction with its time
cd quartus/jtag && quartus_sh -t build.tcl rtl2      # board build, after the simulation passes
```

GHRD: copy this folder to `ip/mlkem_rtl2` in the GHRD project and set `CORE` to `mlkem_rtl2` in `quartus/ghrd/add_mlkem_to_ghrd.tcl`.

## 5. Bringing it up

Same plan as v1 (`hw/manual/README.md`, section 6): compile, fix hangs using the trace, then compare KeyGen outputs piece by piece against the C model. Things specific to v2 to check first:

1. **Bank mapping.** Every writer and reader must agree on bank {w[0], ^w}, address w[6:2]:
   - the ALU crossbars;
   - the sampler group writes;
   - the IO engine's per-word bank select.

   A quick test is DEC then ENC of one polynomial (a round trip through the IO engine only).
2. **NTT word selection.** In `mlkem2_alu.v`, the insertion of zero bits at p and q, and the second zeta for p = 0.
3. **ALU pipeline timing.** Read data from the RAMs (after the 12-slot mux) goes first into the input registers `cq`/`aq`/`bq` at vld[1], and arithmetic starts at vld[2]. NTT/INTT writes back at vld[7], PWM at vld[12], ADD/SUB at vld[3]. In the fused INTT, the second operand is read at vld[5] and lands in `aq` at vld[6], ready with the butterfly results at vld[7]. The IO engine works the same way:
   - DEC-accumulate reads with `prod` and registers the old word in `q2_old`;
   - ENC registers the RAM word in `eq_w` before the compress shift and add.

   The INTT butterfly's first stage (`addhalf`/`subhalf` in `mlkem2_arith.v`) computes (a+b)/2 and (b−a)/2 mod q with one adder level instead of three chained adders. The three possible sums are formed in parallel and picked by parity and sign; this was checked against the old formula for all q² input pairs.

   No path runs from a RAM output through an adder or multiplier in one clock. Those paths set the Fmax in the first two Quartus compiles: first RAM → fused add → RAM (42.8 MHz), then RAM → INTT butterfly input.
4. **Hazard masks.** If the trace shows an instruction stalled forever, print `hz_h`, `hz_a`, `hz_i` and the stored masks in `mlkem2_core.v`.
5. **Sampler staging buffer.** `mlkem2_parse` must produce exactly 32 group writes. A missing last group would hang the Keccak engine in SQZ.
6. **Mailbox banks.** Words 2L (low) and 2L+1 (high) form lane L. A swapped bank shows up at once in H(ek) (the testbench's KeyGen dk check).

## 6. Next steps for more speed

1. **Stream matrix entries straight into the multiplier** (HPKA-style FIFO between the sampler and the ALU): the row time becomes the sampling time, with no buffer write and read-back. The sampler writes aligned groups already, so a FIFO of groups would do.
2. **8 butterflies** (radix-2² step over 4 banks, two layers per pass): NTT ~150 cycles.
3. **IO engine at 2 words per clock:** the ENC/DEC steps at the start and end of each operation are on the critical path (about 135 cycles each).
4. **A second ALU**, or pointwise multiplies overlapping NTTs, to lift the one-ALU-operation-at-a-time limit that bounds all three programs now.
