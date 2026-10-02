# ML-KEM in hardware with Bambu HLS, on the DE10-Nano

This project takes **ML-KEM** (FIPS 203, the NIST post-quantum key-encapsulation standard) written in plain C, turns it into Verilog with the **Bambu** high-level-synthesis (HLS) tool, and runs it on a **Terasic DE10-Nano** (Intel Cyclone V SoC, 5CSEBA6U23I7).

```
 src/*.c ──► Bambu HLS ──► mlkem_accel.v ──► + Avalon wrapper ──► Platform Designer ──► Quartus ──► DE10-Nano
  (C that also                (FSM + datapath)    (hw/rtl)            component                          │
   runs on a PC)                                                                                          │
                                                   your PC ── USB/JTAG ── System Console  ◄──────────────┤ path A
                                                   ARM Linux on the board ── /dev/mem    ◄──────────────┘ path B
```

The default parameter set is **ML-KEM-768** (k = 3). The C code also supports ML-KEM-512 and ML-KEM-1024.

## Contents

1. [What has been checked, and what you run yourself](#1-what-has-been-checked-and-what-you-run-yourself)
2. [Folder map](#2-folder-map)
3. [Install the tools](#3-install-the-tools)
4. [Bambu in ten minutes: the GCD example](#4-bambu-in-ten-minutes-the-gcd-example)
5. [How the ML-KEM C code is written for HLS](#5-how-the-ml-kem-c-code-is-written-for-hls)
6. [Step 1: test the C code](#6-step-1-test-the-c-code)
7. [Step 2: generate Verilog with Bambu](#7-step-2-generate-verilog-with-bambu)
8. [Step 3: the Avalon wrapper and its simulation](#8-step-3-the-avalon-wrapper-and-its-simulation)
9. [Step 4: package the Platform Designer component](#9-step-4-package-the-platform-designer-component)
10. [Step 5 (path A): stand-alone FPGA design, tested from the PC](#10-step-5-path-a-stand-alone-fpga-design-tested-from-the-pc)
11. [Step 6 (path B): the ARM cores and Linux drive the accelerator](#11-step-6-path-b-the-arm-cores-and-linux-drive-the-accelerator)
12. [Size, timing and speed](#12-size-timing-and-speed)
13. [Making it faster](#13-making-it-faster)
14. [Troubleshooting](#14-troubleshooting)
15. [Security notes](#15-security-notes)
16. [References](#16-references)

---

## 1. What has been checked, and what you run yourself

Checked in this project's build environment (Linux, Bambu 2024.10, Verilator 5):

| Check | Result |
|---|---|
| C code against the official NIST ACVP test vectors: KeyGen, Encaps, Decaps (valid and rejected), ek and dk input checks | 80 of 80 per parameter set, for ML-KEM-512, -768 and -1024 |
| Exhaustive checks of the arithmetic tricks (every input of `mod_q`, every Compress/Decompress value), 500 random round trips per parameter set | pass |
| Bambu co-simulation: the generated Verilog runs `hls/tb_accel.c` (7 checks with NIST vectors) and its memory is compared with the C run | pass |
| RTL simulation of the complete accelerator (Avalon wrapper + Bambu core) driven as a bus master would drive it, with NIST vectors | pass |
| The System Console test script and the ARM program, run against a software model of the accelerator | pass |
| The ARM program cross-compiled for Cortex-A9 and run under QEMU in software mode | pass |

The results above are for the current version, in which every datapath block exists once in hardware (`src/hls.h`, section 5). The first version put 39 copies of the Keccak permutation into the hardware, far too many for the DE10-Nano (section 7).

**Not run here: Quartus.** Intel's download server does not allow automated downloads, so the Quartus project, the Platform Designer scripts and the timing were not tried with the real tools. They follow Intel's documented formats and Intel's own DE10-Nano reference scripts (pin locations are copied from them), but expect that you may have to fix a small thing on first compile. Section 14 lists the likely ones.

---

## 2. Folder map

```
src/                   the ML-KEM implementation (C99, no malloc, no libc needed)
  mlkem_params.h         parameter set (MLKEM_K = 2, 3 or 4)
  fips202.c/.h           SHA3-256, SHA3-512, SHAKE128, SHAKE256
  poly.c/.h              polynomial arithmetic, NTT, sampling, encoding
  mlkem.c/.h             K-PKE and ML-KEM (FIPS 203 algorithms 13-18) + input checks
  mlkem_accel.c/.h       the function Bambu turns into hardware + mailbox layout
  hls.h                  inline/leaf attributes that decide the hardware hierarchy
test/                  test_acvp.c (NIST vectors), test_unit.c (exhaustive checks)
vectors/               NIST ACVP vectors as text, one file per parameter set
hls/                   mlkem_hls.c: the one file Bambu compiles (includes src/*.c)
                       tb_accel.c: testbench Bambu uses for co-simulation; tb_vectors.h
hw/bambu/              Bambu output: mlkem_accel.v, mlkem_accel.sv, *.mem (checked in)
hw/rtl/                mlkem_avalon.v (bus wrapper), mlkem_tdp_ram.v (mailbox RAM)
hw/manual/             a hand-written RTL core with the same interface (first version,
                       not yet simulated): see hw/manual/README.md
hw/manual_v2/          v2 of that core: techniques of the fastest papers + low-power
                       RTL (passes the NIST-vector simulation): see hw/manual_v2/README.md
hw/manual_v3/          v3: parallel Keccak / NTT / pointwise / IO engines, 8-butterfly
                       NTT (not yet simulated): see hw/manual_v3/README.md
hw/sim/                tb_mlkem_avalon.sv + vectors/*.hex: RTL simulation
quartus/ip/mlkem_accel/  Platform Designer component (made by "make ip")
quartus/jtag/          path A: stand-alone design + System Console test
quartus/ghrd/          path B: script that adds the accelerator to Terasic's GHRD
sw/mlkem_hps.c         path B: Linux program for the ARM cores
scripts/               vector conversion, IP packaging, Keccak code generator
Makefile               the Linux/WSL steps (make help)
```

---

## 3. Install the tools

Bambu only runs on Linux. On Windows, use **WSL2** (Ubuntu 24.04) for the C, Bambu and simulation steps, and the Windows version of **Quartus** for the FPGA steps.

**Keep the project in the Linux file system** (e.g. `~/mlkem_hls`), not on the Windows drive (`/mnt/c/...`), and in a path **without spaces**. Bambu's co-simulation scripts break on spaces and may fail on the Windows drive, and everything runs much faster in the Linux file system. Quartus on Windows reaches the same folder as `\\wsl$\Ubuntu-24.04\home\<user>\mlkem_hls` (type it in Explorer's address bar), or copy the whole project folder to a Windows folder when you get to the FPGA steps.

After installing the tools below, `make check-env` checks everything Bambu's co-simulation needs.

### 3.1 Linux / WSL side

```bash
sudo apt update
sudo apt install build-essential gcc-multilib python3 verilator make
```

`gcc-multilib` matters: Bambu's GCC front end compiles for 32-bit x86 and needs the 32-bit C headers.

**ARM cross compiler (optional, for path B).** On Ubuntu, `gcc-arm-linux-gnueabihf` and `gcc-multilib` conflict: installing the cross compiler silently **removes** `gcc-multilib`, and Bambu's co-simulation then fails with `asm/errno.h: No such file or directory`. Pick one of:

- skip the cross compiler and compile the ARM program on the board (section 11.3);
- install it, then restore the one header link Bambu needs (tested with this project):
  ```bash
  sudo apt install gcc-arm-linux-gnueabihf
  sudo ln -s x86_64-linux-gnu/asm /usr/include/asm
  ```
- or unpack Arm's stand-alone GNU toolchain for `arm-none-linux-gnueabihf` (developer.arm.com) under `/opt` and build with `make sw-arm CROSS=/opt/<toolchain>/bin/arm-none-linux-gnueabihf-`.
 Verilator must be version 5 or newer (`verilator --version`); Ubuntu 22.04 ships 4.x, which is too old for the RTL testbench (use 24.04 or build Verilator from source).

**Bambu** is distributed as an AppImage (one executable file). Download it from the PandA project (link in section 16) and:

```bash
chmod +x bambu-2024.10.AppImage
sudo mv bambu-2024.10.AppImage /usr/local/bin/bambu     # or anywhere on PATH
sudo apt install libfuse2t64        # Ubuntu 24.04 (libfuse2 on 22.04): AppImages need FUSE
bambu --version
```

If the AppImage refuses to start (FUSE is sometimes unavailable in WSL or containers), unpack it instead:

```bash
./bambu-2024.10.AppImage --appimage-extract          # creates squashfs-root/
sudo mv squashfs-root /opt/bambu
sudo ln -s /opt/bambu/AppRun /usr/local/bin/bambu
```

### 3.2 Windows (or Linux) side: Quartus

Install **Quartus Prime Lite Edition** (free) with **Cyclone V** device support from Intel's FPGA download center. Any version from 18.1 on should work; the Platform Designer scripts use the version-16.1 script API, which newer versions still accept. The USB-Blaster II driver is in `<install>\quartus\drivers`; Windows usually installs it when you first plug in the board's mini-USB "USB Blaster" port.

---

## 4. Bambu in ten minutes: the GCD example

HLS tools read a C function and build a circuit that computes it. Bambu (from Politecnico di Milano's PandA project) does it in the classic way:

1. **Front end:** a C compiler (GCC or Clang, bundled with Bambu) parses and optimises the code into an intermediate form.
2. **Scheduling:** every operation is assigned to a clock cycle (a *control step*), so that the chain of operations in one cycle fits in the clock period you asked for, using delay models of the target FPGA.
3. **Binding:** operations are mapped onto hardware units (adders, multipliers, memories) and values onto registers, sharing units between cycles where possible.
4. **Output:** a Verilog module with a finite-state machine (the controller) and a datapath. Each C function becomes a module; calls become instances with a start/done handshake.

Here is the smallest useful example:

```c
// gcd.c
#include <stdint.h>
uint32_t gcd(uint32_t a, uint32_t b)
{
   if(a == 0) return b;
   if(b == 0) return a;
   while(a != b)
   {
      if(a > b) a = a - b;
      else      b = b - a;
   }
   return a;
}
```

```c
// test_gcd.c - Bambu runs this on the PC, records every call to gcd(),
// then replays the calls on the generated Verilog and compares the results
#include <assert.h>
#include <stdint.h>
uint32_t gcd(uint32_t a, uint32_t b);
int main(void)
{
   assert(gcd(48, 18) == 6);
   assert(gcd(1071, 462) == 21);
   assert(gcd(0, 42) == 42);
   return 0;
}
```

```bash
bambu gcd.c --top-fname=gcd --compiler=I386_GCC8 --clock-period=20 \
      --generate-tb=test_gcd.c --simulate --simulator=VERILATOR
```

Bambu writes `gcd.v`. Its top module is:

```verilog
module gcd(clock, reset, start_port, a, b, done_port, return_port);
  input clock, reset, start_port;
  input  [31:0] a, b;
  output done_port;
  output [31:0] return_port;
```

The protocol: put `a` and `b` on the inputs, pulse `start_port` for one clock, wait for `done_port`, read `return_port`. The while loop became a state machine doing one subtraction per clock, so the time depends on the inputs, just like the loop count in software. `results.txt` lists the simulated cycles per call, and the log reports the flip-flop count (66 for GCD with the GCC 8 front end).

Options you will use most:

| Option | Meaning |
|---|---|
| `--top-fname=f` | the C function that becomes the top module |
| `--clock-period=20` | target clock period in ns (20 ns = 50 MHz). Bambu packs as many operations into a cycle as fit |
| `--device-name=...` | FPGA whose delay models are used for scheduling; `5CSEMA5F31C6` is Bambu's Cyclone V model |
| `--compiler=I386_GCC8` | front-end compiler bundled in the AppImage (see section 7 for why not Clang) |
| `--generate-tb=file.c --simulate` | co-simulation: run the C testbench, then the same calls on the RTL, and compare |
| `--simulator=VERILATOR` | simulator for co-simulation (ICARUS and others also work) |
| `--generate-interface=INFER` | build array/pointer ports from `#pragma HLS interface` lines |
| `--reset-level=high` | active-high reset (the default is active low) |
| `-O1`, `-O2`, `-O3` | front-end optimisation level |

One lesson from GCD worth knowing before the big design: Bambu's delay model is only an estimate. With the default settings the GCD module scheduled for 20 ns was later found (in an ASIC flow) to miss 20 ns slightly; asking Bambu for a tighter clock (`--clock-period=10`) split the logic across more cycles and gave comfortable slack. The real timing check is always the vendor tool (Quartus here).

---

## 5. How the ML-KEM C code is written for HLS

ML-KEM is: hash functions from the Keccak family (SHA-3/SHAKE), arithmetic on polynomials with 256 coefficients modulo q = 3329, the number-theoretic transform (NTT) to multiply those polynomials quickly, and bit packing. The code follows FIPS 203 closely (function names and comments refer to its algorithm numbers) and is also ordinary portable C, so the same file is tested on the PC, synthesised by Bambu, and compiled for the ARM.

Choices made for hardware:

- **No malloc, no recursion, fixed sizes.** Every array has a size known at compile time, so Bambu can turn each into a block RAM or registers.
- **Keccak as straight-line code.** `keccak_f1600()` keeps the 25 lanes in 25 local `uint64_t` variables and writes out one round lane by lane (generated by `scripts/gen_keccak.py`). Bambu turns the lanes into 64-bit registers and a round into XOR/AND/NOT logic, instead of reading a 25-entry array from memory one lane at a time.
- **No division.** `x mod 3329` is a multiply by 5039 and a shift by 24, then one conditional subtraction (Barrett reduction; `test/test_unit.c` checks it for all 2^24 inputs). Compress's division by q is a multiply by 2580335 and a shift by 33, exact for every input it gets. A hardware divider would be large and slow.
- **Small integer types.** Coefficients are `uint16_t`, products `uint32_t`, so the datapaths are only as wide as needed. Bambu maps the multipliers onto Cyclone V DSP blocks.
- **Implicit rejection without a data-dependent branch.** Decaps compares the re-encrypted ciphertext with the received one by OR-ing all byte differences, and selects the real or the rejection key with a mask.
- **One instance of every datapath block.** Bambu turns each C function into a module and gives every *calling module* its own instance, so copies multiply down the call tree. `src/hls.h` therefore splits the code in two: the datapath **leaves** (`keccak_f1600`, `keccak_sponge`, `poly_ntt`, `poly_basemul_acc`, the encoders, ...) are never inlined and are called only from the top function, while everything above them (SHA-3 wrappers, sampling, K-PKE, ML-KEM) is always inlined into `mlkem_accel()`. The whole algorithm becomes one controller that calls one instance of each leaf. For this to work the compiler must see all the code at once, so Bambu compiles `hls/mlkem_hls.c`, which `#include`s every source file. `keccak_sponge()` is the only function that touches a Keccak state (absorb, padding and squeeze all go through it), and it is the only caller of the permutation.
- **A mailbox interface.** The top function `mlkem_accel(op, mem)` works on one 8 KB byte array. Bambu turns that array into a RAM port (`#pragma HLS interface port=mem mode=array elem_count=8192`); inputs and outputs sit at fixed offsets (`src/mlkem_accel.h`). The top function copies inputs from the mailbox into local buffers and results back, because Bambu (2024.10) cannot pass an interface array down to other functions.

---

## 6. Step 1: test the C code

```bash
make test
```

Builds and runs `test/test_acvp.c` for k = 2, 3, 4 against the NIST vectors in `vectors/`, the exhaustive unit tests, and checks that the Keccak code matches its generator. Expected (abridged):

```
ML-KEM-768: keygen 25, encaps 25, decaps 10, ek check 10, dk check 10 -> 80 passed, 0 failed
[PASS] mod_q for all 2^24 inputs
[PASS] Compress_d / Decompress_d for every value, d = 1, 4, 5, 10, 11
[PASS] ML-KEM-768: 500 random KeyGen/Encaps/Decaps round trips + tampered ciphertexts
```

The vectors were extracted from NIST's ACVP server repository (`scripts/acvp_to_txt.py`, section 16). To regenerate them: `make vectors ACVP_JSON=/path/to/ACVP-Server/gen-val/json-files`.

Always get the C right first: a wrong C program becomes wrong hardware, and it is a thousand times faster to debug in C.

---

## 7. Step 2: generate Verilog with Bambu

```bash
make hls        # a few minutes; "make hls-nosim" skips the co-simulation
```

This runs, in `build/hls/`:

```bash
bambu hls/mlkem_hls.c \
      --top-fname=mlkem_accel -Isrc -Ihls \
      --generate-interface=INFER --compiler=I386_GCC8 \
      --device-name=5CSEMA5F31C6 --clock-period=20 --reset-level=high \
      -O2 --disable-function-proxy \
      --generate-tb=hls/tb_accel.c --simulate --simulator=VERILATOR
```

then checks that the co-simulation passed and copies `mlkem_accel.v`, `mlkem_accel.sv` and the `*.mem` files to `hw/bambu/`. The co-simulation prints:

```
[PASS] KeyGen: ek and dk match NIST
[PASS] Encaps: K and c match NIST
[PASS] Decaps: valid ciphertext, K matches NIST
[PASS] Decaps: modified ciphertext, implicit-rejection K matches NIST
[PASS] Encaps rejects an ek that fails the modulus check
[PASS] Decaps rejects a dk that fails the hash check
[PASS] unknown operation code is rejected
```

`hw/bambu/` already holds the Verilog generated from the current C code (co-simulated and RTL-simulated), so you can go straight to the Quartus part. Rerun `make hls` after every change to the C code.

If `make hls` fails, it prints the compiler or simulator messages that explain why (Bambu itself only says "The simulation does not end correctly") and a likely fix; the full log is `build/hls/bambu.log`. `make check-env` checks the usual causes first.

**What comes out.** `mlkem_accel.v` (about 70,000 lines, 101 modules): the top module `mlkem_accel` with its controller, one module per leaf function, and Bambu's library cells. The top module's ports:

```
clock, reset, start_port, op[31:0]                    -> done_port, return_port[31:0]
mem_address0/1[12:0], mem_ce0/1, mem_we0/1, mem_d0/1[7:0], mem_q0/1[7:0]
```

`op` and `return_port` are the C argument and return value. The `mem_*` signals are two independent byte-wide RAM ports to the 8 KB mailbox, with the read data (`mem_q`) expected one clock after the address. The `*.mem` files hold initial contents of Bambu's internal memories (the constant tables such as the NTT twiddle factors and the Keccak round constants), loaded with `$readmemb`.

**Cycle counts** measured through the Avalon wrapper in the RTL simulation, at 50 MHz (about 12% fewer than the first version, which had the 39 Keccak copies). `make hls` also prints them per call (`build/hls/results.txt`, in half-cycles).

| Operation (ML-KEM-768) | Clock cycles | Time at 50 MHz |
|---|---|---|
| KeyGen | 141,790 | 2.84 ms |
| Encaps (including the ek check) | 167,298 | 3.35 ms |
| Decaps (including the dk check) | 221,888 | 4.44 ms |

**Lessons from getting this to work** (useful for any Bambu project):

- **Use `--compiler=I386_GCC8`.** With a Clang front end, Bambu also compiles the co-simulation testbench with its bundled clang-16, which needs `libtinfo.so.5`; Ubuntu 24.04 no longer ships it, and the co-simulation then fails with "The simulation does not end correctly". (On Ubuntu 22.04 `sudo apt install libtinfo5` fixes that.)
- **`--disable-function-proxy` with `-O2`.** With `-O2` and Bambu's default *function proxies* (sharing one hardware instance of a function between several callers) the generated Verilog gave wrong results in co-simulation, while the C was right. The co-simulation caught it; narrowing it down showed the proxy mechanism. Turning proxies off (or using `-O1`) fixes it. `-O2 --disable-function-proxy` was about 12% faster than `-O1`. **Moral: always co-simulate.**
- **`elem_count` is required** on the interface pragma for an array parameter.
- **Interface arrays can only be used in the top function.** Passing `mem` to another function gives "interfacing not supported"; hence the copy-in/copy-out in `mlkem_accel()`.
- **Bambu duplicates functions per call path.** A function gets one instance inside every module that calls it, and those modules are themselves duplicated by their callers. In the first version `keccak_f1600` was reached through 39 different paths (e.g. `mlkem_accel` → `mlkem_decaps_internal` → `kpke_encrypt` → `poly_sample_cbd` → `shake256` → `keccak_squeeze` → `keccak_f1600`), so the Verilog contained **39 Keccak permutations** of about 3,700 flip-flops each, plus 4 NTTs, 4 base multipliers and so on: far more than the DE10-Nano holds. Counting module instances in the generated Verilog (not just module definitions) is how to find this. The fix is the leaf/inline split in `src/hls.h` (section 5); afterwards every leaf has exactly one instance.

---

## 8. Step 3: the Avalon wrapper and its simulation

The Bambu core has a start/done handshake and RAM ports. To reach it from the PC (JTAG) or from the ARM cores, `hw/rtl/mlkem_avalon.v` wraps it as an **Avalon-MM slave**, the bus used inside Intel FPGA systems: 32-bit data, byte enables, word addresses, fixed read latency of one clock, no wait states.

The mailbox is built from four byte-wide dual-port RAMs (`hw/rtl/mlkem_tdp_ram.v`, written so Quartus infers M10K block RAMs without vendor IP): the bus reads and writes 32-bit words across the four lanes, while the core, which has two byte-wide ports, reaches any byte from either port. While the core runs it owns the RAM.

**Register map** (byte offsets from the component's base address, 16 KB span):

| Offset | Name | Access | Meaning |
|---|---|---|---|
| 0x0000-0x1FFF | mailbox | R/W | 8 KB, layout below. Do not touch while BUSY |
| 0x2000 | CTRL | W | write 1 (KeyGen), 2 (Encaps) or 3 (Decaps) to start; ignored while busy |
| 0x2004 | STATUS | R/W | bit 0 BUSY, bit 1 DONE; write 2 to clear DONE |
| 0x2008 | RESULT | R | 0 OK, 1 key failed its input check, 2 unknown operation |
| 0x200C | CYCLES | R | clock cycles the last operation took |
| 0x2010 | ID | R | 0x4D4C4B4D ("MLKM") |
| 0x2014 | PARAMS | R | k (3 for ML-KEM-768) |
| 0x2018 | IRQ_EN | R/W | bit 0: interrupt output = DONE |

**Mailbox layout** (`src/mlkem_accel.h`, room for ML-KEM-1024):

| Offset | Size (768) | Content | KeyGen | Encaps | Decaps |
|---|---|---|---|---|---|
| 0x0000 | 32 | d | in | | |
| 0x0020 | 32 | z | in | | |
| 0x0040 | 32 | m | | in | |
| 0x0060 | 32 | shared secret K | | out | out |
| 0x0100 | 1184 | ek | out | in | |
| 0x0800 | 2400 | dk | out | | in |
| 0x1800 | 1088 | ciphertext c | | out | in |

Software sequence: write inputs → write op to CTRL → poll STATUS until DONE (or wait for the interrupt) → read RESULT and outputs → write 2 to STATUS.

Note that the randomness (d, z, m) comes from software, as in the "internal" functions of FIPS 203: the hardware has no random number generator. Use a good one (`/dev/urandom` on Linux).

Simulate the whole accelerator the way a bus master drives it:

```bash
make sim-rtl        # Verilator; about a minute
```

```
[PASS] ID = 0x4D4C4B4D ("MLKM"), PARAMS = 3 (ML-KEM-768)
[PASS] mailbox write/read with byte enables
[PASS] KeyGen: ek, dk match NIST (141790 cycles)
[PASS] Encaps: c, K match NIST (167298 cycles)
[PASS] Decaps (valid): K matches NIST (221888 cycles)
[PASS] Decaps (modified c): implicit-rejection K matches NIST, IRQ fired, 2nd start ignored
[PASS] unknown operation returns status 2
TEST PASSED
```

---

## 9. Step 4: package the Platform Designer component

```bash
make ip
```

`scripts/package_ip.py` copies the four Verilog files and the `.mem` files into `quartus/ip/mlkem_accel/` and writes `mlkem_accel_hw.tcl`, the component description Platform Designer reads. The component, shown in the IP Catalog as **Cryptography > ML-KEM accelerator (Bambu HLS)**, has four interfaces: `clock`, `reset` (active high, synchronous), `avalon_slave` (16 KB) and `irq`.

The folder is self-contained, so you can copy it into any Quartus project's `ip/` folder. It is already filled in from `hw/bambu/`; run `make ip` after every Bambu run.

---

## 10. Step 5 (path A): stand-alone FPGA design, tested from the PC

The quickest way to see the accelerator on the board: no ARM software, no SD card. The design contains only the accelerator and a **JTAG-to-Avalon master**, which lets **System Console** on the PC read and write the accelerator's registers over the board's USB cable.

```
FPGA_CLK1_50 ──► clk_0 ──┬──► master_0 (JTAG-to-Avalon) ──► mlkem_0 at 0x0000
KEY0 (reset) ─┘          └──────────────────────────────────►
LED0: heartbeat      LED7: reset held
```

### 10.1 Build

Open a **Quartus command shell** (on Windows: a Command Prompt with `C:\intelFPGA_lite\<version>\quartus\bin64` added to PATH), then:

```bat
cd C:\path\to\mlkem_hls\quartus\jtag
quartus_sh -t build.tcl
```

`build.tcl` does everything:

1. copies the `.mem` files into `quartus/jtag` (Quartus looks for `$readmemb` files in the project folder);
2. creates the Platform Designer system `mlkem_system.qsys` with `qsys-script` from `mlkem_system_qsys.tcl`;
3. generates its Verilog with `qsys-generate`;
4. creates the Quartus project `de10_nano_mlkem` (device 5CSEBA6U23I7, pins, 3.3-V LVTTL, `de10_nano_mlkem.sdc` with the 50 MHz clock);
5. compiles it and prints the resource and timing summaries.

Compilation of a design this size takes roughly 10-30 minutes depending on the PC. Use `quartus_sh -t build.tcl nocompile` to stop after step 4 and compile from the GUI instead (File > Open Project > `de10_nano_mlkem.qpf`, then Processing > Start Compilation).

Check two things in the output:

- **Fitter summary:** logic utilization in ALMs (the device has 41,509), block memory bits and DSP blocks all below 100%.
- **Timing (`.sta.summary`):** the **Setup slack** for `clk50` must be **positive** (at the slow corner). If not, see section 12.2.

You can open `mlkem_system.qsys` in Platform Designer (Tools > Platform Designer) to see the system, and the RTL Viewer (Tools > Netlist Viewers) to see the generated hardware.

### 10.2 Program the board

1. Connect the DE10-Nano's **USB-Blaster II** mini-USB port to the PC (the board has two mini-USB ports; the other one is the ARM's serial console), and power the board. Leave the SW10 switches as they are; JTAG programming works with any setting.
2. Quartus > Tools > **Programmer** > Hardware Setup: select **DE-SoC [USB-1]**.
3. Click **Auto Detect**. The JTAG chain has two devices: the ARM part (**SOCVHPS**) and the FPGA; if asked which FPGA, choose **5CSEBA6**.
4. Right-click the **5CSEBA6** device > Change File > `quartus/jtag/output_files/de10_nano_mlkem.sof`, tick **Program/Configure**, click **Start**.

Or from the command line:

```bat
quartus_pgm -l
quartus_pgm -c 1 -m jtag -o "p;output_files/de10_nano_mlkem.sof@2"
```

(`@2` is the FPGA, the second device in the chain.) LED0 now blinks.

If Linux is running on the board from the SD card, that is fine: the new FPGA image replaces the one U-Boot loaded, until the next power cycle.

### 10.3 Run the test from System Console

Quartus > Tools > System Debugging Tools > **System Console**. In the Tcl Console at the bottom:

```tcl
cd C:/path/to/mlkem_hls/quartus/jtag
source mlkem_test.tcl
```

(Use forward slashes in Tcl paths on Windows.) Expected:

```
[PASS] ID register = 0x4D4C4B4D (expect 0x4D4C4B4D), k = 3
[PASS] KeyGen: ek and dk match NIST (141790 cycles = 2.84 ms at 50 MHz)
[PASS] Encaps: ciphertext and shared secret match NIST (167298 cycles = 3.35 ms at 50 MHz)
[PASS] Decaps (valid ciphertext): shared secret matches NIST (221888 cycles = 4.44 ms at 50 MHz)
[PASS] Decaps (modified ciphertext): implicit-rejection secret matches NIST (about 220800 cycles = 4.42 ms at 50 MHz)
[PASS] Encaps rejects an ek that fails the modulus check (status 1)
[PASS] Decaps rejects a dk that fails the hash check (status 1)
[PASS] round trip 1: Encaps and Decaps agree, tampered ciphertext rejected
...
ALL TESTS PASSED
```

The script uses the same NIST vectors as the simulations (`hw/sim/vectors/*.hex`), then runs random KeyGen → Encaps → Decaps round trips. The cycle counts come from the CYCLES register, so they are the hardware's own measurement and should equal the simulation's.

You can also poke the registers by hand, which is a good way to understand the interface:

```tcl
set m [claim_service master [lindex [get_service_paths master] 0] demo]
master_read_32 $m 0x2010 1            ;# ID -> 0x4d4c4b4d
master_write_32 $m 0x2000 1           ;# start KeyGen (on whatever d, z are in the mailbox)
master_read_32 $m 0x2004 1            ;# STATUS: 0x2 = DONE
master_read_32 $m 0x200C 1            ;# CYCLES
master_read_8  $m 0x0100 16           ;# first bytes of ek
close_service master $m
```

---

## 11. Step 6 (path B): the ARM cores and Linux drive the accelerator

In a real system the DE10-Nano's dual-core ARM Cortex-A9 (the **HPS**, hard processor system) would use the accelerator. The HPS reaches FPGA logic through the **lightweight HPS-to-FPGA bridge**, a 2 MB window at physical address **0xFF200000**. A component at base address `0x40000` on that bridge appears to Linux at `0xFF240000`.

You need:

- **Terasic's DE10-Nano GHRD** (Golden Hardware Reference Design): the Quartus project with the HPS already configured. It is in the DE10-Nano **System CD** download on Terasic's DE10-Nano page (folder `Demonstrations/SoC_FPGA/DE10_NANO_SoC_GHRD`).
- A **Linux SD card image** for the DE10-Nano from the same page (the "Console" or "LXDE Desktop" image). Terasic's images have U-Boot configure the FPGA at boot from **`soc_system.rbf`** on the SD card's FAT partition.

Adding a peripheral on the lightweight bridge does not change the HPS configuration, so the preloader, U-Boot and device tree on the SD card stay as they are; only the FPGA image changes.

### 11.1 Add the accelerator to the GHRD

1. Copy the GHRD folder somewhere (e.g. `C:\de10\ghrd`) and open `DE10_NANO_SoC_GHRD.qpf` in Quartus. If Quartus is newer than the GHRD it offers to upgrade the IP; accept.
2. Copy the folder `quartus/ip/mlkem_accel` from this project into the GHRD's `ip\` folder (create it if missing), so it becomes `C:\de10\ghrd\ip\mlkem_accel\`.
3. Copy all `*.mem` files from that folder into the GHRD **project folder** itself (`C:\de10\ghrd\`), where Quartus looks for them.
4. Tools > **Platform Designer**, open `soc_system.qsys`.
5. In the IP Catalog, find **ML-KEM accelerator (Bambu HLS)** under Cryptography (if it is missing: Tools > Options > IP Search Path, add the `ip` folder, then File > Refresh). Double-click, Finish. It appears as `mlkem_accel_0`.
6. Connect it like the GHRD's other small peripherals (e.g. `led_pio`) by clicking the dots in the Connections column:
   - `clock` ← `clk_0.clk`
   - `reset` ← `clk_0.clk_reset`
   - `avalon_slave` ← `hps_0.h2f_lw_axi_master`
7. In the **Base** column, set its base address to **0x0004_0000** (any free, 16 KB-aligned address works; Platform Designer reports overlaps).
8. Leave `irq` unconnected (the Linux program polls). Check the Messages pane: only the warning about the unconnected interrupt should be new.
9. **Generate HDL** (Verilog, synthesis), save, close Platform Designer.
10. Back in Quartus: **Processing > Start Compilation**. Check fitter utilization and timing as in 10.1.

Steps 4-9 can also be done with the script `quartus/ghrd/add_mlkem_to_ghrd.tcl` (run from the GHRD folder: `qsys-script --script=add_mlkem_to_ghrd.tcl --search-path=ip/**/*,$`, then `qsys-generate soc_system.qsys --synthesis=VERILOG --search-path=ip/**/*,$`). Instance names differ between GHRD versions; the script checks them and tells you what it found.

### 11.2 Put the new FPGA image on the board

**Quick (until the next power cycle):** boot Linux from the SD card as usual (U-Boot loads the original GHRD and enables the bridges), then program `output_files/DE10_NANO_SoC_GHRD.sof` over JTAG exactly as in 10.2. The bridges stay enabled, and the accelerator is there.

**Permanent:** convert the `.sof` to the raw binary format U-Boot loads, and replace the file on the SD card:

```bat
quartus_cpf -c output_files\DE10_NANO_SoC_GHRD.sof soc_system.rbf
```

Copy `soc_system.rbf` over the one on the SD card's FAT partition (keep a backup of the original). This is for the board's default SW10 setting (all ON, FPP x16, which the DE10-Nano manual lists as "FPGA configured from HPS software: U-Boot"). If you changed SW10 to the FPP x32 setting (MSEL 01010, which enables compression), create a compressed file instead: `quartus_cpf -c -o bitstream_compression=on ...`.

### 11.3 Build and run the Linux program

`sw/mlkem_hps.c` maps the accelerator's registers through `/dev/mem`, then:

1. checks ID and PARAMS (a wrong address stops it here);
2. runs the NIST known-answer tests on the FPGA;
3. generates random seeds from `/dev/urandom`, gives the same seeds to the FPGA and to the same C code running on the ARM, and requires every key, ciphertext and shared secret to be **bit-identical**, including the implicit-rejection key for a tampered ciphertext;
4. prints timing for the FPGA core, the FPGA including the mailbox copies, and the ARM software;
5. clears the mailbox (so no key material is left in it).

Cross-compile on the PC (WSL) and copy to the board:

```bash
make sw-arm                                  # -> build/mlkem_hps (static, Cortex-A9)
scp build/mlkem_hps root@<board-ip>:         # or copy it via the SD card
```

or compile on the board if it has gcc (copy `src/`, `hls/tb_vectors.h` and `sw/` over):

```bash
gcc -O2 -Isrc -Ihls sw/mlkem_hps.c src/fips202.c src/poly.c src/mlkem.c -o mlkem_hps
```

Run it on the board (root is needed for `/dev/mem`):

```bash
sudo ./mlkem_hps                 # accelerator at 0xFF240000 (base 0x40000)
sudo ./mlkem_hps -a 0xFF250000   # if you chose another base address
./mlkem_hps -s                   # software only, no FPGA needed
```

Expected output format (the numbers are what you measure; the FPGA core cycles should match section 7):

```
ML-KEM-768, k = 3
accelerator at 0xFF240000: ID 0x4D4C4B4D, k = 3
[PASS] FPGA KeyGen: ek, dk match NIST ACVP
...
100 / 100 random round trips: FPGA output identical to the ARM software

average over 100 rounds   FPGA core        FPGA + copies   ARM software
  KeyGen          141790 cyc =  2.836 ms      ...            ...
```

On a PC you can test the program without a board: `make sw-emu` builds it with a software model of the accelerator (it calls the same `mlkem_accel()` C function that Bambu compiled).

**Warning:** accessing the bridge while the FPGA is not configured, or while the bridge is held in reset, can hang the ARM. Program the FPGA first.

---

## 12. Size, timing and speed

### 12.1 Size

The DE10-Nano's FPGA has **41,509 ALMs, 5,570 Kbit of M10K block RAM and 112 DSP blocks**. The Quartus fitter report (`output_files/*.fit.summary`, printed at the end of `build.tcl`) gives the exact use; it was not measured here.

What to expect:

- **Flip-flops:** Bambu reports about **16,700** for the restructured core: 8,951 in the top module (controller and its registers), 3,746 in the single Keccak permutation, and 64 to 1,017 in each of the other leaves. The device has 166,036. (The first version had about 3,700 × 39 ≈ 146,000 in Keccak permutations alone.)
- **Block RAM:** the core's local arrays add up to about 210 Kbit in 193 small memories, plus the 64 Kbit mailbox, against 5,570 Kbit (553 M10K blocks). Quartus puts the smallest ones in MLABs or registers.
- **DSP blocks:** a few dozen at most; the multipliers are 16x16 and 32-bit constant multiplications.
- **ALMs:** the number to watch in the fitter report. With one instance of each leaf the core should use a moderate part of the 41,509; the largest parts are the controller of the inlined top function and the Keccak round logic.

If you change the C code, keep the rule from section 5: a function that calls a leaf must be `MLKEM_API`/`MLKEM_LOCAL` (inlined), and a leaf must not call another leaf. Otherwise the copies come back; count the instances in the new Verilog to check.

### 12.2 Timing closure

Bambu scheduled the design for 20 ns using delay models of a Cyclone V **C6** speed grade (`5CSEMA5F31C6`, the chip on the DE1-SoC board). The DE10-Nano's 5CSEBA6U23**I7** is a slower speed grade, so some paths may miss 20 ns. If the Timing Analyzer reports negative setup slack for `clk50`:

1. **Look at the worst paths first** (Timing Analyzer > Report Top Failing Paths). If they are inside the Bambu core, go to 2. If they are in the wrapper or the interconnect, they are easy to pipeline.
2. **Ask Bambu for a shorter period**, e.g. `--clock-period=15` in the Makefile's `BAMBU_FLAGS`, while still running the board at 50 MHz. Bambu then puts less logic in each cycle: more cycles, but each is shorter. Rerun `make hls sim-rtl ip`, then rebuild.
3. **Or run slower**: add a PLL (IP Catalog > PLL > Altera PLL) to make 40 MHz or 25 MHz from the 50 MHz input, drive the system from it, and change the SDC and the `CLOCK_MHZ`/`CLOCK_HZ` values in the test programs. Cycle counts stay the same; time per operation grows.
4. Quartus settings that help a little: Assignments > Settings > Compiler Settings > **Performance (High effort)**.

### 12.3 Speed

At 50 MHz the accelerator takes about **2.8 ms (KeyGen), 3.3 ms (Encaps) and 4.4 ms (Decaps)**.

Be ready for this: **the ARM will probably be faster.** The DE10-Nano's Cortex-A9 runs at 800-925 MHz, and the same C code there most likely needs on the order of a millisecond per operation (measure it: `mlkem_hps -s`, or look at the last column of `mlkem_hps`). For comparison, it takes about 0.1 ms on a current PC. The accelerator is an unoptimised, straight translation of sequential C running at a clock 16-18 times slower; each loop iteration costs several cycles and nothing runs in parallel yet. That is normal for a first HLS result, and it is where the real HLS work starts (next section). What you have now is the part that is hardest to get right: a **correct**, standard-conforming hardware ML-KEM with a verified path from C to the board.

---

## 13. Making it faster

In order of payoff:

1. **Keccak.** Most of the time is spent in SHAKE and SHA-3 (matrix sampling alone runs SHAKE128 many times). The permutation is already straight-line code, but `keccak_sponge()` moves one byte at a time. Absorbing and squeezing 64-bit words instead of bytes cuts that part several-fold. Computing two rounds per loop iteration (unroll by 2) halves the permutation's cycles, if timing allows.
2. **Parallel NTT butterflies.** The NTT loops do one butterfly at a time because a `poly` lives in one block RAM with two ports. Splitting the coefficient array into several smaller arrays (even/odd, or four banks) lets Bambu schedule two or four butterflies per cycle.
3. **Parallel leaves.** Now that each leaf exists once, everything runs strictly one after the other. Independent work (for example sampling the next matrix entry with Keccak while the base multiplier works on the current one) could overlap if the leaves were given their own buffers and started without waiting; in C this means restructuring loops so the tool can see the independence, or duplicating a leaf on purpose where it pays off.
4. **Pipelining and unrolling.** Bambu can pipeline loops and unroll them (see its documentation for the loop pragmas and options); apply them to the innermost loops of sampling and encoding.
5. **Wider mailbox.** The wrapper reads and writes 32-bit words, but the core sees bytes. A 32-bit or 64-bit core interface would shorten the copy-in/copy-out loops.
6. **Clock.** After the above, see how fast Quartus lets the design run (Fmax in the timing report) and set the clock accordingly.

Every change: `make test` (C still right) → `make hls` (co-simulation passes, cycles go down) → `make sim-rtl` → Quartus. The C tests and the co-simulation are what make these experiments safe.

**The hand-written alternative.** `hw/manual` contains the same accelerator written directly in Verilog: a microcoded sequencer driving a Keccak engine, a polynomial ALU and an encode/decode engine that work in parallel. It has the same registers and mailbox, so the testbench, `mlkem_test.tcl` and `mlkem_hps` work unchanged. Its estimated cost is about 5,900 / 6,900 / 9,300 cycles for KeyGen / Encaps / Decaps, roughly 24 times fewer than the Bambu core. It is a first version that has not been simulated yet. Bring it up with `make sim-manual` (see `hw/manual/README.md`), then build it with `quartus_sh -t build.tcl rtl`.

`hw/manual_v2` goes further with techniques from the fastest published designs: 4 butterflies, hazard checking in hardware so the engines overlap, 2 Keccak rounds per clock, a faster sampler, fused operations. It also applies low-power RTL techniques: clock enables on every pipeline, RAM read enables, operand isolation. It passes the NIST-vector simulation with 2,867 / 3,375 / 4,737 cycles: `make sim-v2`, `quartus_sh -t build.tcl rtl2`.

`hw/manual_v3` aims below the fastest published FPGA design (HPKA, 1,700 / 2,400 / 3,000 cycles). It splits the work over four engines that run in parallel (Keccak, NTT, pointwise, IO), uses an 8-butterfly radix-4 NTT whose passes chain without draining, lets Keccak permute while the sampler reads the previous block, and decodes two words per clock. Estimated cycles: about 1,390 / 1,430 / 2,070. Not simulated yet: `make sim-v3`, `quartus_sh -t build.tcl rtl3`.

---

## 14. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `make hls`: "The simulation does not end correctly" | the co-simulation could not be built or run; `make hls` now prints the underlying message and a likely fix. Run `make check-env`: the usual causes are missing 32-bit headers, a path with spaces, the project on `/mnt/c`, or too little memory in WSL |
| `mdpi.h: fatal error: svdpi.h: No such file or directory` | Bambu looks for Verilator's headers next to the `verilator` command, which fails when that command is a symlink or wrapper (Verilator built from source, OSS CAD Suite, ...). The Makefile now passes Verilator's real include folder (`verilator --getenv VERILATOR_ROOT`) through `CPATH`; when running Bambu by hand, `export CPATH=$(verilator --getenv VERILATOR_ROOT)/include/vltstd` first |
| `bambu`: `bits/libc-header-start.h: No such file` | `sudo apt install gcc-multilib` |
| `bambu`: `asm/errno.h: No such file`, "The simulation does not end correctly" | `gcc-multilib` was removed by installing the ARM cross compiler: see section 3.1 |
| `inlining failed in call to 'always_inline' ...` | a function marked `MLKEM_API`/`MLKEM_LOCAL` cannot be inlined (recursion, or its address is taken); keep those functions plain |
| the generated Verilog is much larger after a C change | a leaf got a second caller path: see the rule at the end of section 12.1 |
| `bambu`: error about `libtinfo.so.5` | you used a Clang front end: use `--compiler=I386_GCC8` |
| AppImage: `dlopen(): error loading libfuse.so.2` | install `libfuse2t64` (24.04) / `libfuse2` (22.04), or use `--appimage-extract` (section 3.1) |
| co-simulation reports a mismatch after you changed the C code | first check the C with `make test`; if the C is right, try `-O1` instead of `-O2`, or other Bambu versions; keep `--disable-function-proxy` |
| `make sim-rtl`: Verilator errors about `--timing` or `--binary` | Verilator is older than 5.0 |
| `build.tcl`: `cannot find qsys-script` | add `<quartus install>/quartus/sopc_builder/bin` to PATH, or set `QUARTUS_ROOTDIR` |
| Platform Designer: `mlkem_accel` component not found | the search path must include `quartus/ip`: check the `--search-path` argument, or Tools > Options > IP Search Path in the GUI |
| Quartus: error about a missing `.mem` file, or the core gives wrong results on the board although simulation passed | the `.mem` files are not in the Quartus project folder: copy them there (`build.tcl` does it for path A) |
| Quartus: `Can't place ... I/O standard` | a pin assignment is missing: all used pins need `3.3-V LVTTL` |
| Timing: negative setup slack | section 12.2 |
| Programmer: no hardware | install the USB-Blaster II driver; use the mini-USB port marked USB Blaster; board powered |
| Programmer: `.sof` does not match the device | right-click the FPGA (5CSEBA6), not SOCVHPS; on the command line use `@2` |
| System Console: `no JTAG master found` | the `.sof` is not programmed, or another tool holds the cable (close SignalTap) |
| System Console test: ID reads 0 or garbage | wrong `mlkem_base` (0 in path A), or the FPGA was reprogrammed with another design |
| System Console test: timeout waiting for DONE | the core is stuck: press KEY0 (reset) and retry; if persistent, check timing |
| Linux: `mlkem_hps` hangs | FPGA not configured or bridges disabled: boot the SD image normally (U-Boot enables the bridges), then program the FPGA |
| Linux: `no ML-KEM accelerator ... at this address` | wrong `-a` (0xFF200000 + your base address) or the GHRD `.sof`/`.rbf` without the accelerator is loaded |
| Linux: `cannot open /dev/mem` | run with `sudo` |
| U-Boot does not configure the new `.rbf` | compression setting does not match SW10 (section 11.2); file must be named `soc_system.rbf` |

---

## 15. Security notes

This is a teaching and experimentation project.

- The C code implements FIPS 203 and passes NIST's ACVP known-answer vectors, but it has **not been reviewed for side channels** (timing, power, electromagnetic). Coefficient reductions and the implicit-rejection selection avoid data-dependent branches, but no one has analysed the generated hardware. It is **not** a validated cryptographic module (no CMVP/FIPS 140-3 validation).
- The randomness (d, z, m) must come from a cryptographically secure source. The System Console script uses Tcl's `rand()`, which is **not** secure; it is only for testing. The Linux program uses `/dev/urandom`.
- The mailbox keeps keys and secrets until overwritten. Both test programs clear it at the end; do the same in your own software.
- Anyone with root on the ARM, or with the JTAG cable, can read the mailbox.
- For real use, prefer an established, reviewed implementation (for software, for example PQClean or liboqs).

---

## 16. References

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*: https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 202, *SHA-3 Standard*: https://csrc.nist.gov/pubs/fips/202/final
- NIST ACVP server repository (test vectors in `gen-val/json-files/ML-KEM-*`): https://github.com/usnistgov/ACVP-Server
- Bambu / PandA project: https://panda.dei.polimi.it and https://github.com/ferrandi/PandA-bambu
- Terasic DE10-Nano (user manual, System CD with the GHRD, Linux SD images): https://www.terasic.com.tw (search "DE10-Nano")
- DE10-Nano user manual (Intel FPGA University Program mirror): https://ftp.intel.com/Public/Pub/fpgaup/pub/Intel_Material/Boards/DE10-Nano/DE10_Nano_User_Manual.pdf
- Intel's DE10-Nano reference design scripts (pin assignments, Platform Designer scripting): https://github.com/intel/de10-nano-hardware
- Intel: *Avalon Interface Specifications*; *Quartus Prime Standard Edition User Guide: Platform Designer*; *Cyclone V Hard Processor System Technical Reference Manual* (HPS-to-FPGA bridges) - on intel.com
