# PQSE secure element v1.5

v1.5 is the v4 secure element (`hw/se`) with three changes:

1. The host chooses ML-KEM-512, ML-KEM-768 or ML-KEM-1024 for each command.
2. Pointwise multiplication (PWM) uses Karatsuba: 4 clocks per coefficient pair instead of 6.
3. Reduction mod q needs no multiplier.

Everything else is unchanged: masking, hiding, fault detection, PUF key wrapping and secure messaging. `hw/se/README.md` describes those, and this file only covers what differs.

**Status.** The RTL is written and elaborates without errors in slang, the same way as v4. It has not been simulated. `make sim-se-v1.5` runs the v4 functional tests on the ML-KEM-768 vectors; the other two parameter sets have no test vectors yet (see "Not done yet").

## Choosing the key size

| Register | Bits | Meaning |
|---|---|---|
| `0x406` CONFIG | [2:1] | Parameter set for the next KEYGEN, KGWRAP, UNWRAP, IMPORT or ENCAPS: 0 = ML-KEM-768 (default after reset), 1 = ML-KEM-512, 2 = ML-KEM-1024. A write of 3 leaves the setting unchanged. [0] is still hiding on/off. |
| `0x403` STATUS | [20:19] | Parameter set of the loaded key, same coding |
| `0x401` VERSION | | `0x00010500` |

- **DECAPS** always uses the parameter set of the loaded key, whatever CONFIG says.
- **UNWRAP** uses CONFIG, so the host must select the same parameter set it used for KGWRAP. The blob holds only d and z. Unwrapping with a different setting gives a different, unrelated key pair: FIPS 203 hashes k into G(d ‖ k), so it is not a weaker key, but it is not the stored one either.
- **SEAL and OPEN** do not depend on the parameter set.

Sizes per parameter set (k = 2, 3, 4):

| | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| ek | 800 B | 1,184 B | 1,568 B |
| ciphertext | 768 B | 1,088 B | 1,568 B |
| du, dv (bits per ciphertext coefficient) | 10, 4 | 10, 4 | 11, 5 |
| eta1 (noise range for s, e, y) | 3 | 2 | 2 |

## Buffer map

The buffer is still 512 lanes of 64 bits (4 KB). The windows are sized for ML-KEM-1024. To fit, ENCAPS writes its ciphertext over the peer's ek in `B_XIN` instead of into a separate output window.

Lane addresses (word address = 2 × lane):

| Lanes | Window | Host access |
|---|---|---|
| 0 to 195 | Own ek: t̂ in 48-lane parts, then rho at lane 48k | read; write in TEST and PERSO |
| 196 to 211 | PUF helper data and key check value | read, write |
| 212 to 407 | `B_XIN`: peer ek, ciphertext in and out, s^ bytes (IMPORT), raw dumps | write; read only after ENCAPS, PUFRAW or TRNGRAW |
| 408 to 411 | K | read in TEST and PERSO |
| 412 to 427 | Injected d, z, m, H(ek) | as in v4 |
| 428 to 441 | Wrapped-key blob | read, write |
| 444 to 467 | Secure message | read, write |
| 468 to 471 | `B_TMP`: rho of the key in use | never |

`B_XIN` becomes readable when an ENCAPS, PUFRAW or TRNGRAW ends with result 0. It stops being readable when the next command starts or the host writes into the window.

This rule matters because of IMPORT. In TEST and PERSO, IMPORT takes the secret key's s^ bytes in `B_XIN`. It overwrites them with zeros once they are loaded, so they can never be read back later.

How ENCAPS writes in place:
1. Check the peer ek (every t̂ coefficient below q) and hash it.
2. Copy its rho to `B_TMP`.
3. Compute v, which reads t̂, and write c2 at lane DU·k.
4. Compute each u_i and write c1 part i at lane DU·i, over t̂ parts that are no longer needed.

DU is 40 lanes (44 for k = 4) and c2 is 16 lanes (20 for k = 4). The ciphertext is the first DU·k + DV lanes of `B_XIN`. Any ek bytes after it are public.

## Memories and slots

The polynomial RAMs grow from 2 × 1024 × 25 to 2 × 1280 × 25: 20 slots of 128 words instead of 16. ML-KEM-1024 needs s^ (8 slots) and y (8 slots) at the same time as the four working slots. Even slots are in RAM 0, odd slots in RAM 1, as before.

| Slots | Contents |
|---|---|
| 0 to 7 | s^_j: share 0 in slot 2j, share 1 in slot 2j + 1 |
| 8 to 15 | y_j, or e_i / t_i during KeyGen: slots 8 + 2j and 9 + 2j |
| 16 | T (matrix entry or decoded public polynomial) |
| 17 | Z (all zeros, for precharge reads) |
| 18, 19 | ACC, share 0 / share 1 |

The I/O buffer stays 4 KB and the seed RAMs stay 2 × 64 × 65. The scratch area for PRF output (`E_CBD`) now covers seed entries 10 to 15, 24 lanes. That is room for ML-KEM-512's 192-byte eta = 3 output.

## Microcode with loops

v4's programs were unrolled for k = 3 and took 793 ROM words. v1.5 loops over the k polynomials of a vector and fits in 501 (addresses 0 to 500).

`C_LOOP` (class 8) increments counter i or j. If the result is below the limit, it jumps back; otherwise it clears the counter and falls through. The limit is k, or a constant (ZEROIZE uses 10).

Before an engine starts, the sequencer (`pqse_core.v`) translates the instruction's index-dependent fields for the current i, j and k:

- **Slots.** 4-bit logical codes become 5-bit physical slots: `L_SJ0` = share 0 of s^_j, `L_YI1` = share 1 of y_i, `L_T`, `L_Z`, `L_ACC0`, `L_ACC1`.
- **d.** `D_DU` and `D_DV` become du and dv.
- **Buffer lane.** Modes `AM_48I`, `AM_48J`, `AM_48K`, `AM_DUI` and `AM_DUK` add 48·i, 48·j, 48·k, DU·i or DU·k lanes.
- **Hash jobs** (`HM_*`):
  - matrix A: the XOF bytes (j, i), or (i, j) for the transpose;
  - PRF nonces: i, k + i, or 2k, with eta1 or eta2 setting the output length (128 or 192 bytes);
  - H(ek) length: 48k + 4 lanes;
  - J(z ‖ c) length: ciphertext lanes for k;
  - the k byte of G(d ‖ k).

k, i and j have complemented shadow copies, like the program counter. A mismatch counts as a fault.

The programs live in `scripts/pqse_ucode_v15_gen.py`, which lays them out, resolves labels to addresses and writes the case table into `pqse_ucode.v`. To change the microcode, edit the script and run `python3 scripts/pqse_ucode_v15_gen.py`. It checks that the entry points still match `EP_*` in `pqse_defs.vh`. If the layout moves, update the fault-injection addresses at the top of `hw/sim/tb_pqse_v15.sv` by hand.

## Arithmetic changes

**Reduction mod q without multipliers** (`pqse_arith.v`). q = 2^12 − 2^9 − 2^8 + 1, so each product bit at position 12 or above stands for a small constant mod q:

| Bit | Constant | Bit | Constant | Bit | Constant |
|---|---|---|---|---|---|
| 12 | 767 | 16 | −1,044 | 20 | −59 |
| 13 | 1,534 | 17 | 1,241 | 21 | −118 |
| 14 | −261 | 18 | −847 | 22 | −236 |
| 15 | −522 | 19 | 1,635 | 23 | −472 |

The low 12 bits, plus these constants, plus 2q, give a 14-bit value between 3,099 and 15,930. Comparing it with q, 2q, 3q and 4q and subtracting once gives the result. This replaces Barrett reduction's two constant multiplications (37 and 25 bits) in the multiplier and in the mask generator `pqse_modq24`. It is exact for every 24-bit input (all 2^24 checked in Python). HOPE-MLKEM (TCHES 2026) uses the same folding.

**Karatsuba PWM** (`pqse_poly.v`). The polynomial unit computes, per coefficient pair:

```
m1 = a0·b0    m2 = a1·b1    m3 = (a0 + a1)(b0 + b1)    m5 = m2·γ
c0' = c0 + m1 + m5          c1' = c1 + m3 − m1 − m2
```

That is 4 multiplications instead of 5, so the one shared multiplier is busy every clock. A PWM takes about 524 clocks instead of 780. Each pair reads a, b and c and writes its result three passes later; the comment at the PWM case shows the schedule.

**Masked Compress for d = 5 and 11** (`pqse_mcomp.v`). For d = 11 the scaled shares would need 25 bits, so d = 11 uses 13 guard bits instead of 14 and stays at 24 bits. The worst-case error, 1.05 units, is still below the 1.23 margin. d = 1, 4, 5, 10 and 11 were checked exhaustively in Python: every coefficient, every split into two shares.

**Masked CBD for eta = 3** (`pqse_masked.v`). Six bits per coefficient with weights +1, +1, +1, −1, −1, −1. A 12-bit word of the PRF output can straddle two lanes (words 5 and 10 of every 16), so the B2A conversion loads the next lane mid-word from a bit-position register.

## Estimated cycles

From a cost model of the microcode that reproduces v4's measured ML-KEM-768 clocks to within 3 %. These are estimates; the CYCLES register gives the real numbers in simulation.

| Command | ML-KEM-512 | ML-KEM-768 (v4 measured) | ML-KEM-1024 |
|---|---|---|---|
| KeyGen with fault checks and PCT | ~370 k | ~534 k (545 k) | ~780 k |
| Encaps | ~170 k | ~263 k (268 k) | ~384 k |
| Decaps | ~200 k | ~295 k (298 to 305 k) | ~420 k |

At 3.39 MHz, the contactless clock, ML-KEM-1024 Encaps takes about 115 ms and Decaps about 125 ms. ML-KEM-768 gets about 2 % faster than v4 from the Karatsuba PWM. The command watchdog (2^22 clocks) leaves room for ML-KEM-1024 KGWRAP (about 0.83 M clocks).

## Area and power compared with v4

| Part | Change |
|---|---|
| Polynomial RAMs | +25 % (2 × 256 more words): the cost of ML-KEM-1024 at runtime |
| I/O buffer, seed RAMs | unchanged |
| Microcode ROM | 501 words in use instead of 793 |
| Multiplier and mask reduction | adder trees instead of two constant multipliers each |
| Polynomial unit | 4 registers (48 bits) for the Karatsuba sums |
| Sequencer | the translation adders and the loop counters |

The multiplier is active in roughly 25,000 clocks of an ML-KEM-768 Encaps (NTTs, INTTs and PWMs), so a smaller, shallower reduction saves energy in each of them. Area and energy still have to be measured with `make se-area-v1.5` and a power run.

## Make targets

```
make sim-se-v1.5       # functional tests, ML-KEM-768 vectors (hw/sim/tb_pqse_v15.sv)
make se-area-v1.5      # Yosys cell count (SKY130_LIB=... for sky130)
make se-gowin-v1.5     # fit on the Tang Nano 20K
```

`se-area` and `se-gowin` take `SE_DIR=hw/se_v1_5`. The `-v1.5` targets set it.

## Not done yet

1. **Vectors for ML-KEM-512 and -1024.** Generate NIST ACVP vectors with `scripts/acvp_to_txt.py` and `scripts/make_tb_vectors.py`. Then add sections to `tb_pqse_v15.sv` that set CONFIG[2:1] and use per-set sizes for EK, DK and CT.
2. **The other testbenches.** `tb_pqse_tvla.sv`, `tb_pqse_fault.sv` and `tb_pqse_gate.sv` still target v4's map and addresses.
3. **Probing check.** `scripts/pqse_probe_verify.py` models v4's gadget schedules. Two schedules are new and need to be added: the eta = 3 CBD with its mid-word lane reload, and Compress with 13 guard bits.
4. **Power flow.** `se-power*` still builds `hw/se`.
