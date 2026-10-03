# PQSE diagrams

Mermaid diagrams of the PQSE secure element (v4, `hw/se`). GitHub renders them in place; elsewhere, paste a block into [mermaid.live](https://mermaid.live). Names in `code` are RTL modules, instances, microcode labels or Makefile targets. The text explanations are in [`PQSE_design.md`](PQSE_design.md) and [`hw/se/README.md`](../hw/se/README.md).

1. [System overview](#1-system-overview)
2. [Module hierarchy](#2-module-hierarchy)
3. [Share domains and memories](#3-share-domains-and-memories)
4. [Masked AND gadget (DOM)](#4-masked-and-gadget-dom)
5. [Sequencer state machine](#5-sequencer-state-machine)
6. [Lifecycle and security state](#6-lifecycle-and-security-state)
7. [A command and the fault response](#7-a-command-and-the-fault-response)
8. [KeyGen with its fault checks](#8-keygen-with-its-fault-checks)
9. [Masked Decaps](#9-masked-decaps)
10. [PUF key and key wrapping](#10-puf-key-and-key-wrapping)
11. [Secure messaging](#11-secure-messaging)
12. [Verification and energy flow](#12-verification-and-energy-flow)

## 1. System overview

The host talks to a 32-bit register bus through SPI (chip) or Avalon-MM (FPGA). `pqse_host` owns the lifecycle, the access rules and the fault response; `pqse_core` runs one engine at a time under microcode.

```mermaid
flowchart LR
    reader["Card reader / host CPU"]
    subgraph pins["Chip pins"]
        spi["SPI, 4 pins"]
        tamper["tamper in"]
        irq["IRQ out"]
        trig["trigger out<br/>(TEST only)"]
    end
    reader <--> spi
    subgraph chip["pqse_top"]
        spis["pqse_spi<br/>SPI slave"]
        subgraph host["pqse_host"]
            regs["registers<br/>ID, CTRL, STATUS, CYCLES,<br/>LIFECYCLE, CONFIG"]
            policy["lifecycle and<br/>command policy"]
            wd["watchdog, 2^22 clocks"]
            wipe["wipe on power-on,<br/>fault, tamper"]
            nvm["pqse_nvm<br/>persistent security state"]
        end
        buf["I/O buffer 4 KB<br/>(host access only when idle)"]
        subgraph core["pqse_core"]
            seq["sequencer +<br/>microcode ROM 1024 x 96"]
            eng["engines<br/>Keccak / sponge, poly unit,<br/>masked gadgets, I/O, SampleNTT, PUF"]
            mem["share-domain RAMs<br/>polynomial, seed, Keccak state"]
            rng["TRNG, Trivium PRNG,<br/>Fisher-Yates shuffler"]
        end
    end
    spi <--> spis
    spis <-->|"32-bit register bus"| regs
    tamper --> wipe
    host --> irq
    core --> trig
    regs -->|"command, start"| seq
    seq -->|"result, done"| regs
    regs <-->|"buffer windows"| buf
    seq --> eng
    eng <--> mem
    eng <--> buf
    rng --> eng
    policy --- nvm
```

## 2. Module hierarchy

Instance names as in the RTL. `pqse_avalon` replaces `pqse_top` on the FPGA; both wrap `pqse_sys`.

```mermaid
flowchart TB
    top["pqse_top (chip)<br/>or pqse_avalon (FPGA)"] --> spi["u_spi : pqse_spi"]
    top --> sys["u_sys : pqse_sys"]
    sys --> host["u_host : pqse_host"]
    sys --> core["u_core : pqse_core"]
    host --> nvm["u_nvm : pqse_nvm"]
    core --> rom["u_rom : pqse_ucode"]
    core --> trng["u_trng : pqse_trng"]
    trng --> ro["u_src : pqse_ro_src"]
    core --> prng["u_prng : pqse_prng (Trivium)"]
    core --> perm["u_perm : pqse_perm (Fisher-Yates)"]
    core --> sponge["u_sponge : pqse_sponge"]
    sponge --> keccak["u_keccak : pqse_keccak"]
    keccak --> ks["u_s0, u_s1 : pqse_ram_1r1w<br/>Keccak state 64 x 65, one per share"]
    core --> parse["u_parse : pqse_parse (SampleNTT)"]
    core --> poly["u_poly : pqse_poly (NTT, INTT, PWM, ADD, SUB, ZCHK)"]
    core --> io["u_io : pqse_io (encode, decode, seed ops, SEQ)"]
    core --> masked["u_masked : pqse_masked (CBD/B2A, mu, select, ok copies)"]
    masked --> mcomp["u_mc : pqse_mcomp (masked Compress)"]
    core --> puf["u_puf : pqse_puf (fuzzy extractor)"]
    puf --> praw["u_raw : pqse_puf_raw (960 cells)"]
    core --> pm["u_pmem0, u_pmem1 : pqse_ram_1r1w<br/>polynomial RAM 1024 x 25"]
    core --> sr["u_seed0, u_seed1 : pqse_ram_1r1w<br/>seed RAM 64 x 65"]
    core --> bu["u_blo, u_bhi : pqse_ram_1r1w<br/>I/O buffer 512 x 32 each"]
```

## 3. Share domains and memories

Every secret is two shares. Share 0 and share 1 never sit in the same RAM, bus or read register; they meet only inside registered DOM gadgets, which produce either new shares or a value that is public by design.

```mermaid
flowchart LR
    subgraph d0["Domain 0"]
        pm0["polynomial RAM 0<br/>even slots: share 0 + public"]
        sd0["seed RAM 0<br/>share 0 of d, z, m, K, KEK, ..."]
        ks0["Keccak state RAM 0"]
    end
    subgraph d1["Domain 1"]
        pm1["polynomial RAM 1<br/>odd slots: share 1"]
        sd1["seed RAM 1<br/>share 1"]
        ks1["Keccak state RAM 1"]
    end
    subgraph gad["Registered DOM gadgets"]
        chi["Keccak chi"]
        b2a["CBD / B2A"]
        cmp["Compress, ciphertext compare,<br/>two ok copies"]
        sel["implicit-rejection select"]
    end
    pub["Public outputs only<br/>ek (t-hat, rho), ciphertext,<br/>tag check result, OKCHK"]
    ntt["poly unit: NTT, INTT, PWM<br/>run once per share"]
    pm0 <--> ntt
    pm1 <--> ntt
    ks0 --> chi
    ks1 --> chi
    sd0 --> b2a
    sd1 --> b2a
    pm0 --> cmp
    pm1 --> cmp
    sd0 --> sel
    sd1 --> sel
    chi --> ks0
    chi --> ks1
    b2a --> pm0
    b2a --> pm1
    cmp --> pub
```

## 4. Masked AND gadget (DOM)

The building block of every nonlinear masked step (Keccak chi, the Compress adder, the ok accumulators, the select). With z = x AND y and x = x0 XOR x1, y = y0 XOR y1, the two cross terms are refreshed with a fresh random bit r and every partial product is registered before the shares are combined.

```mermaid
flowchart LR
    x0["x0"] --> p00["register<br/>x0 AND y0"]
    y0["y0"] --> p00
    x0 --> p01["register<br/>(x0 AND y1) XOR r"]
    y1["y1"] --> p01
    x1["x1"] --> p10["register<br/>(x1 AND y0) XOR r"]
    y0 --> p10
    x1 --> p11["register<br/>x1 AND y1"]
    y1 --> p11
    r["fresh random r<br/>(PRNG)"] --> p01
    r --> p10
    p00 --> z0["z0 = p00 XOR p01<br/>(compress register)"]
    p01 --> z0
    p10 --> z1["z1 = p11 XOR p10<br/>(compress register)"]
    p11 --> z1
```

## 5. Sequencer state machine

`pqse_core`, register `q` with its complemented shadow `q_n`. A shadow mismatch, a pc shadow mismatch, an instruction parity error or an engine that never reported busy raises a fault from any state.

```mermaid
stateDiagram-v2
    [*] --> Q_IDLE
    Q_IDLE --> Q_FETCH: command start, pc set to entry point
    Q_IDLE --> Q_IDLE: unknown command, result 6
    Q_FETCH --> Q_PG: ROM read done (2 clocks)
    Q_FETCH --> Q_IDLE: TRNG failed, result 5
    Q_PG --> Q_PW: shuffled instruction, hiding on
    Q_PG --> Q_DLY: no permutation needed
    Q_PW --> Q_DLY: Fisher-Yates order drawn
    Q_DLY --> Q_EXEC: after 0 to 15 random dummy clocks
    Q_EXEC --> Q_WAIT: engine started
    Q_EXEC --> Q_FETCH: BR or SET, next pc
    Q_EXEC --> Q_RSD: SET reseed
    Q_EXEC --> Q_IDLE: END, result, done
    Q_WAIT --> Q_FETCH: engine idle, pc + 1
    Q_RSD --> Q_RSW: 3 TRNG words collected
    Q_RSW --> Q_FETCH: PRNG reseeded
```

## 6. Lifecycle and security state

The lifecycle only moves forward. The fault counter, the tamper flag and the lifecycle each have a complemented shadow and live in the persistent store `pqse_nvm`, written before the next command is accepted.

```mermaid
stateDiagram-v2
    [*] --> TEST
    TEST --> PERSO: write LIFECYCLE
    PERSO --> USER: write LIFECYCLE
    TEST --> KILLED: write LIFECYCLE
    PERSO --> KILLED: write LIFECYCLE
    USER --> KILLED: write LIFECYCLE
    TEST --> KILLED: tamper, 3rd fault, shadow or rollback
    PERSO --> KILLED: tamper, 3rd fault, shadow or rollback
    USER --> KILLED: tamper, 3rd fault, shadow or rollback
    KILLED --> [*]
    note right of TEST
        injected seeds, raw PUF / TRNG dumps,
        trigger pin, K readable
    end note
    note right of PERSO
        key import, PUF enrollment, K readable
    end note
    note right of USER
        field use: K never leaves the chip,
        it stays masked as the session key
    end note
```

## 7. A command and the fault response

Any detector ends the command with result 8 (FAULT). The host wipes every key and counts the fault before it accepts the next command.

```mermaid
sequenceDiagram
    participant H as Host
    participant P as pqse_host
    participant C as pqse_core
    participant N as pqse_nvm
    H->>P: write buffer inputs (idle only)
    H->>P: write CTRL = command
    P->>P: lifecycle and policy check
    alt not allowed
        P-->>H: STATUS done, result 2 (denied)
    else allowed
        P->>C: command, start
        C->>C: microcode runs, one engine at a time
        alt no detector fired
            C-->>P: result, done
            P-->>H: STATUS done, IRQ
        else a detector fired or the watchdog expired
            C-->>P: result 8 (FAULT)
            P->>C: reset engines
            P->>C: ZEROIZE: wipe RAMs, seeds, buffer windows
            P->>N: program fault count (write-ahead)
            N-->>P: programmed
            P-->>H: STATUS done, result 8, faults counted
            Note over P,N: third fault: lifecycle KILLED
        end
    end
```

## 8. KeyGen with its fault checks

Microcode at 16 (seeds), 80 (G), 720 (s and e twice, then the G check at 790), 106 (t-hat), 608 (pairwise test), 144 (wrap, KGWRAP only), 156 (wipe). Everything is masked until t-hat is complete; t-hat and rho are public.

```mermaid
flowchart TD
    seeds["d, z from the TRNG<br/>conditioned by the masked sponge<br/>(TEST: injected)"]
    g["G(d || 3), masked Keccak<br/>rho public, sigma masked"]
    g2["G(d || 3) again, XORed in: must give 0<br/>(IO_SEQ vs zero entry), rho compared"]
    se1["s0..s2, e0..e2:<br/>PRF, masked CBD, NTT per share"]
    se2["same again with fresh masks<br/>and new word orders"]
    zchk["SUB per share, then ZCHK:<br/>both differences sum to 0?"]
    a["A[i][j] = SampleNTT(rho, j, i)"]
    t["t-hat = A o s-hat + e-hat<br/>PWM per share, then unmasked"]
    ek["ek = encode(t-hat) || rho<br/>H(ek)"]
    pct["pairwise test (608), KEYGEN / KGWRAP:<br/>Encaps to the new ek, Decaps,<br/>K and K' compared share-wise"]
    valid["key valid<br/>s-hat, z stay masked"]
    wrap["KGWRAP: blob =<br/>nonce, Enc_KEK(d || z), tag"]
    wipe["wipe temporaries (156)"]
    fault["FAULT (result 8):<br/>wipe and count"]
    seeds --> g --> se1 --> se2 --> zchk
    zchk -->|"differ"| fault
    zchk --> g2
    g2 -->|"not 0"| fault
    g2 --> a --> t --> ek --> pct
    pct -->|"K != K'"| fault
    pct --> valid --> wrap --> wipe
    valid --> wipe
    ek -->|"UNWRAP: no pairwise test"| valid
```

## 9. Masked Decaps

Microcode at 320. m', K', r', the comparison result and K never exist unmasked. A fault that forces "c' = c" or disturbs one decoding of m' is caught by the two ok copies (OKCHK) and the double decoding (IO_SEQ).

```mermaid
flowchart TD
    c["ciphertext c (public)"]
    w["w = v - INTT(s-hat o NTT(u))<br/>per share"]
    m1["m' = Compress_1(w)<br/>masked, Boolean shares"]
    m2["m' again, fresh masks<br/>and word order"]
    seqchk["IO_SEQ: decodings equal?"]
    gk["(K', r') = G(m' || h)<br/>masked Keccak"]
    kb["K-bar = J(z || c)"]
    reenc["re-encrypt with r':<br/>y, e1, e2 from the masked CBD,<br/>u', v' per share"]
    cmpc["masked Compress of u', v',<br/>each bit compared with c<br/>into two ok copies"]
    okchk["OKCHK: copies agree?"]
    sel["K = ok ? K' : K-bar<br/>masked select"]
    sk["session key (masked)<br/>TEST / PERSO: K to the buffer"]
    fault["FAULT (result 8)"]
    c --> w --> m1 --> m2 --> seqchk
    seqchk -->|"differ"| fault
    seqchk --> gk --> reenc --> cmpc --> okchk
    c --> kb --> sel
    okchk -->|"differ"| fault
    okchk --> sel --> sk
```

## 10. PUF key and key wrapping

The secret key is never stored. The PUF gives a 180-bit key k through an RM(1,5) fuzzy extractor; the key-encryption key KEK = SHA3-256(k ‖ "K") wraps the seed d || z.

```mermaid
flowchart TD
    subgraph enroll["ENROLL (TEST / PERSO)"]
        ek1["k from the TRNG"] --> ek2["read each of 960 cells 5 times,<br/>majority = reference r"]
        ek2 --> ek3["helper w = r XOR C(k)<br/>check value H(k || 'C')"]
    end
    subgraph recon["Key reconstruction (KGWRAP, UNWRAP)"]
        r1["1 read per cell,<br/>masked ML decoding"] --> c1{"check value<br/>matches?"}
        c1 -->|"no"| r3["majority of 3 reads"] --> c3{"matches?"}
        c3 -->|"no"| r5["majority of 5 reads"] --> c5{"matches?"}
        c5 -->|"no"| puferr["result 12 (PUF)"]
        c1 -->|"yes"| kek["KEK = SHA3-256(k || 'K')"]
        c3 -->|"yes"| kek
        c5 -->|"yes"| kek
    end
    ek3 -->|"helper data in the buffer"| r1
    kek --> kgw["KGWRAP: KeyGen, then<br/>blob = nonce, d || z XOR SHAKE256(KEK || nonce), tag"]
    kek --> unw["UNWRAP: masked tag check,<br/>decrypt d || z, KeyGen again"]
    unw -->|"tag wrong"| bad["result 4 (bad blob)"]
```

## 11. Secure messaging

The ML-KEM shared secret stays inside as the masked session key SK. SEAL and OPEN use KMAC256 with direction-specific customization, so a message reflected to its sender fails.

```mermaid
sequenceDiagram
    participant A as Initiator chip
    participant HA as Host A
    participant HB as Host B
    participant B as Responder chip
    HA->>A: ENCAPS(peer ek)
    A-->>HA: ciphertext c (K kept as SK)
    HA->>HB: c
    HB->>B: DECAPS(c)
    Note over B: same K kept as SK
    HA->>A: SEAL(M, length L)
    A->>A: counter += 1, H = counter, L
    A->>A: C = M XOR KMACXOF256(SK, H, "E1")
    A->>A: T = KMAC256(SK, H || C, "T1")
    A-->>HA: H, C, T
    HA->>HB: H, C, T
    HB->>B: OPEN(H, C, T)
    B->>B: counter new and inside the 64-message window?
    B->>B: length and tag check
    alt authentic
        B->>B: mark counter, decrypt
        B-->>HB: M
    else replay or old counter
        B-->>HB: result 11
    else bad tag or length
        B-->>HB: result 9, C left encrypted
    end
```

## 12. Verification and energy flow

The `make` targets and what feeds the reported numbers.

```mermaid
flowchart LR
    rtl["RTL hw/se"]
    subgraph func["Function and security"]
        sim["make sim-se<br/>Verilator, NIST vectors,<br/>17 fault / tamper tests"]
        probe["make se-probe<br/>robust probing check"]
        tvla["make sim-se-tvla<br/>fixed vs random t-test"]
        fc["make sim-se-fault<br/>random bit-flip campaign"]
    end
    subgraph energy["Energy (sky130)"]
        ys["Yosys: map to sky130_fd_sc_hd,<br/>clock gating"]
        gl["Verilator gate-level run<br/>of one KeyGen, SAIF"]
        sta["OpenSTA: power"]
        rep["pqse_energy.py:<br/>energy per command"]
        or["make se-sram-char:<br/>OpenRAM + ngspice<br/>(pqse_openram_run.py)"]
        tab["sram_table.txt<br/>pJ per read / write / idle"]
    end
    rtl --> sim
    rtl --> probe
    rtl --> tvla
    rtl --> fc
    rtl --> ys --> gl --> sta --> rep
    gl -->|"SRAM access counts"| rep
    or --> tab --> rep
```
