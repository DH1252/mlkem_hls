# PQSE diagrams

Diagrams of the PQSE secure element (v4, `hw/se`) in Mermaid. GitHub draws them in place; elsewhere, paste a block into [mermaid.live](https://mermaid.live). Names in `code` are RTL modules, instances, microcode labels or Makefile targets. The design is explained in [`PQSE_design.md`](PQSE_design.md), the RTL in [`hw/se/README.md`](../hw/se/README.md).

Conventions: solid arrows carry data or control, dotted arrows go to a fault or error exit, thick borders mark checks.

1. [System overview](#1-system-overview)
2. [Module hierarchy](#2-module-hierarchy)
3. [Share domains](#3-share-domains)
4. [Masked AND gate (DOM)](#4-masked-and-gate-dom)
5. [Sequencer](#5-sequencer)
6. [Lifecycle](#6-lifecycle)
7. [Command and fault response](#7-command-and-fault-response)
8. [KeyGen](#8-keygen)
9. [Decaps](#9-decaps)
10. [PUF key and key wrapping](#10-puf-key-and-key-wrapping)
11. [Secure messaging](#11-secure-messaging)
12. [Verification and energy flow](#12-verification-and-energy-flow)

## 1. System overview

Three layers: the pins, the host interface `pqse_host`, and the core `pqse_core`, which runs one engine at a time.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart TB
    subgraph L1["Pins"]
        direction LR
        spi["SPI, 4 pins"]
        tamper["tamper in"]
        irq["IRQ out"]
        trig["trigger out, TEST only"]
    end
    subgraph L2["pqse_host"]
        direction LR
        regs["registers<br/>CTRL, STATUS, CYCLES,<br/>LIFECYCLE, CONFIG"]
        policy["lifecycle and<br/>command policy"]
        guard["watchdog, wipe,<br/>fault counter"]
        nvm["pqse_nvm<br/>persistent state"]
    end
    subgraph L3["pqse_core"]
        direction LR
        seq["sequencer<br/>ROM 1024 x 96"]
        eng["engines<br/>Keccak, poly unit,<br/>masked gadgets, I/O,<br/>SampleNTT, PUF"]
        mem["RAMs<br/>polynomial, seed,<br/>Keccak state"]
        buf["I/O buffer 4 KB"]
    end
    spi --> regs
    tamper --> guard
    regs --> irq
    regs --> policy
    policy --> nvm
    regs --> seq
    seq --> eng
    eng --> mem
    eng --> buf
    regs --> buf
    seq --> trig
```

## 2. Module hierarchy

Instance names from the RTL. On the FPGA, `pqse_avalon` takes the place of `pqse_top`; both contain `pqse_sys`.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart TB
    top["pqse_top / pqse_avalon"]
    top --> spi["u_spi<br/>pqse_spi"]
    top --> sys["u_sys<br/>pqse_sys"]
    sys --> host["u_host<br/>pqse_host"]
    sys --> core["u_core<br/>pqse_core"]
    host --> nvm["u_nvm<br/>pqse_nvm"]
    core --> ctl
    core --> eng
    core --> ram
    subgraph ctl["Control and randomness"]
        direction TB
        rom["u_rom<br/>pqse_ucode"]
        trng["u_trng<br/>pqse_trng"]
        prng["u_prng<br/>pqse_prng"]
        perm["u_perm<br/>pqse_perm"]
    end
    subgraph eng["Engines"]
        direction TB
        sponge["u_sponge<br/>pqse_sponge"]
        keccak["u_keccak<br/>pqse_keccak"]
        parse["u_parse<br/>pqse_parse"]
        poly["u_poly<br/>pqse_poly"]
        io["u_io<br/>pqse_io"]
        masked["u_masked<br/>pqse_masked"]
        mcomp["u_mc<br/>pqse_mcomp"]
        puf["u_puf<br/>pqse_puf"]
        sponge --> keccak
        masked --> mcomp
    end
    subgraph ram["RAMs, pqse_ram_1r1w"]
        direction TB
        pm["u_pmem0, u_pmem1<br/>1024 x 25"]
        sd["u_seed0, u_seed1<br/>64 x 65"]
        ks["u_s0, u_s1 in u_keccak<br/>64 x 65"]
        bu["u_blo, u_bhi<br/>512 x 32"]
    end
```

## 3. Share domains

A secret exists as share 0 and share 1. The shares are stored in separate RAMs and meet only inside the registered gadgets in the middle column.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart LR
    subgraph D0["Domain 0"]
        direction TB
        pm0["polynomial RAM 0<br/>share 0 and public"]
        sd0["seed RAM 0"]
        ks0["Keccak state RAM 0"]
    end
    subgraph G["Registered DOM gadgets"]
        direction TB
        chi["Keccak chi"]
        b2a["CBD / B2A"]
        cmp["Compress, compare,<br/>two ok copies"]
        sel["select"]
    end
    subgraph D1["Domain 1"]
        direction TB
        pm1["polynomial RAM 1<br/>share 1"]
        sd1["seed RAM 1"]
        ks1["Keccak state RAM 1"]
    end
    pub["Public results only<br/>ek, ciphertext, tag check, OKCHK"]
    ks0 --- chi --- ks1
    sd0 --- b2a --- sd1
    pm0 --- cmp --- pm1
    sd0 --- sel --- sd1
    cmp --> pub
```

The poly unit (NTT, INTT, PWM) is linear, so it runs once on share 0 and once on share 1 and needs no gadget.

## 4. Masked AND gate (DOM)

z = x AND y with x = x0 XOR x1 and y = y0 XOR y1. The cross terms get a fresh random bit r, and every partial product is registered before the shares are recombined. Keccak chi, the Compress adder, the ok copies and the select all use this gate.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart LR
    subgraph IN["Inputs"]
        direction TB
        x0["x0"]
        y0["y0"]
        r["r, fresh"]
        x1["x1"]
        y1["y1"]
    end
    subgraph PP["Partial products, registered"]
        direction TB
        p00["x0 AND y0"]
        p01["(x0 AND y1) XOR r"]
        p10["(x1 AND y0) XOR r"]
        p11["x1 AND y1"]
    end
    subgraph OUT["Outputs, registered"]
        direction TB
        z0["z0 = p00 XOR p01"]
        z1["z1 = p11 XOR p10"]
    end
    x0 --> p00
    y0 --> p00
    x0 --> p01
    y1 --> p01
    r --> p01
    x1 --> p10
    y0 --> p10
    r --> p10
    x1 --> p11
    y1 --> p11
    p00 --> z0
    p01 --> z0
    p10 --> z1
    p11 --> z1
```

## 5. Sequencer

The `q` register in `pqse_core`. It has a complemented copy `q_n`; a mismatch, a pc-shadow mismatch, an instruction parity error or an engine that never started raises a fault in any state.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart TB
    idle(["Q_IDLE"])
    fetch["Q_FETCH<br/>ROM read, 2 clocks"]
    pg{"Q_PG<br/>shuffled instruction?"}
    pw["Q_PW<br/>draw Fisher-Yates order"]
    dly["Q_DLY<br/>0 to 15 dummy clocks"]
    exec{"Q_EXEC<br/>instruction class"}
    wait["Q_WAIT<br/>until the engine is idle"]
    rsd["Q_RSD<br/>collect 3 TRNG words"]
    rsw["Q_RSW<br/>reseed the PRNG"]
    done(["result, done"])
    idle -->|"command"| fetch
    fetch --> pg
    pg -->|"yes"| pw
    pg -->|"no"| dly
    pw --> dly
    dly --> exec
    exec -->|"engine"| wait
    exec -->|"SET reseed"| rsd
    exec -->|"END"| done
    exec -->|"BR, SET"| fetch
    wait --> fetch
    rsd --> rsw
    rsw --> fetch
    done --> idle
```

## 6. Lifecycle

The lifecycle moves only forward. Writing the LIFECYCLE register moves it one or more states on; the events on the right move it straight to KILLED.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart LR
    test["TEST"] --> perso["PERSO"] --> user["USER"] --> killed(["KILLED"])
    ev["tamper input<br/>third detected fault<br/>shadow mismatch<br/>rolled-back state"] --> killed
    classDef dead stroke-width:3px
    class killed dead
```

| State | Allowed in addition to the normal commands |
|---|---|
| TEST | injected seeds, raw PUF and TRNG dumps, trigger pin, K readable |
| PERSO | key import, PUF enrollment, K readable |
| USER | none; K stays inside as the masked session key |
| KILLED | nothing |

## 7. Command and fault response

Any detector ends the command with result 8 (FAULT). The host then wipes every key and records the fault before it accepts another command.

```mermaid
sequenceDiagram
    participant H as Host
    participant P as pqse_host
    participant C as pqse_core
    participant N as pqse_nvm
    H->>P: buffer inputs, then CTRL = command
    P->>P: lifecycle and policy check
    alt not allowed
        P-->>H: done, result 2
    else allowed
        P->>C: start
        C->>C: microcode, one engine at a time
        alt no fault
            C-->>P: result, done
            P-->>H: STATUS done, IRQ
        else detector or watchdog
            C-->>P: result 8
            P->>C: reset engines, ZEROIZE
            P->>N: program fault count
            N-->>P: programmed
            P-->>H: done, result 8
            Note over P,N: third fault: KILLED
        end
    end
```

## 8. KeyGen

In microcode order: 16 seeds, 80 G, 720 s and e twice, 790 G check, 106 t-hat and ek, 608 pairwise test (KEYGEN and KGWRAP only), 141 key valid, 144 wrap (KGWRAP only), 156 wipe. Everything is masked until t-hat; t-hat and rho are public.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart TB
    seeds["d, z from the TRNG<br/>through the masked sponge"]
    g["G(d || 3)<br/>rho public, sigma masked"]
    se1["s, e: PRF, masked CBD, NTT"]
    se2["s, e again, fresh masks"]
    zchk{"SUB per share, ZCHK:<br/>copies equal?"}
    gchk{"G(d || 3) again:<br/>XOR is 0?"}
    t["t-hat = A o s-hat + e-hat<br/>A from SampleNTT(rho)"]
    ek["ek = encode(t-hat) || rho,<br/>H(ek)"]
    pct{"pairwise test:<br/>K = K'?"}
    valid["key valid"]
    wrap["KGWRAP: wrap d || z"]
    wipe(["wipe temporaries, done"])
    f1(["FAULT"])
    f2(["FAULT"])
    f3(["FAULT"])
    seeds --> g --> se1 --> se2 --> zchk
    zchk -->|"yes"| gchk
    gchk -->|"yes"| t --> ek --> pct
    pct -->|"yes"| valid --> wrap --> wipe
    zchk -.->|"no"| f1
    gchk -.->|"no"| f2
    pct -.->|"no"| f3
    classDef check stroke-width:3px
    class zchk,gchk,pct check
```

UNWRAP derives the same key pair from the unwrapped d and z; it runs the duplicate checks but skips the pairwise test.

## 9. Decaps

Microcode at 320. m', K', r', the comparison result and K are never unmasked.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart TB
    c["ciphertext c"]
    w["w = v - INTT(s-hat o NTT(u))<br/>per share"]
    m1["m' = Compress_1(w)"]
    m2["m' again, fresh masks and order"]
    seqc{"IO_SEQ:<br/>decodings equal?"}
    gk["(K', r') = G(m' || h)"]
    kb["K-bar = J(z || c)"]
    re["re-encrypt with r'<br/>y, e1, e2 from the masked CBD"]
    cmpc["compare each bit of u', v' with c<br/>into two ok copies"]
    okc{"OKCHK:<br/>copies equal?"}
    sel["K = ok ? K' : K-bar<br/>masked select"]
    sk(["session key, masked"])
    f1(["FAULT"])
    f2(["FAULT"])
    c --> w --> m1 --> m2 --> seqc
    seqc -->|"yes"| gk --> re --> cmpc --> okc
    okc -->|"yes"| sel --> sk
    c --> kb --> sel
    seqc -.->|"no"| f1
    okc -.->|"no"| f2
    classDef check stroke-width:3px
    class seqc,okc check
```

## 10. PUF key and key wrapping

No key is stored. The PUF gives a 180-bit key k through an RM(1,5) fuzzy extractor, and KEK = SHA3-256(k ‖ "K") wraps the seed d ‖ z.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart TB
    subgraph EN["ENROLL, TEST or PERSO"]
        direction TB
        e1["k from the TRNG"] --> e2["5 reads per cell, majority = r"] --> e3["helper w = r XOR C(k),<br/>check value H(k || 'C')"]
    end
    subgraph RC["Key reconstruction, KGWRAP and UNWRAP"]
        direction TB
        r1["1 read per cell,<br/>masked decoding"] --> c1{"check value<br/>matches?"}
        c1 -->|"no"| r3["majority of 3 reads"] --> c3{"matches?"}
        c3 -->|"no"| r5["majority of 5 reads"] --> c5{"matches?"}
        c1 -->|"yes"| kek["KEK = SHA3-256(k || 'K')"]
        c3 -->|"yes"| kek
        c5 -->|"yes"| kek
        c5 -.->|"no"| pe(["result 12"])
    end
    e3 -->|"helper data"| r1
    kek --> kgw["KGWRAP: KeyGen, blob =<br/>nonce, encrypted d || z, tag"]
    kek --> unw{"UNWRAP:<br/>tag correct?"}
    unw -->|"yes"| kg["decrypt d || z, KeyGen"]
    unw -.->|"no"| be(["result 4"])
    classDef check stroke-width:3px
    class c1,c3,c5,unw check
```

## 11. Secure messaging

The shared secret stays inside both chips as the masked session key SK. Each direction uses its own KMAC customization ("E1", "T1" from initiator to responder), so a message sent back to its sender fails the tag check.

```mermaid
sequenceDiagram
    participant A as Initiator chip
    participant HA as Host A
    participant HB as Host B
    participant B as Responder chip
    HA->>A: ENCAPS(peer ek)
    A-->>HA: c, K kept as SK
    HA->>HB: c
    HB->>B: DECAPS(c)
    Note over B: same K kept as SK
    HA->>A: SEAL(M, L)
    A->>A: counter + 1, H = counter, L
    A->>A: C = M XOR KMACXOF256(SK, H, E1)
    A->>A: T = KMAC256(SK, H || C, T1)
    A-->>HA: H, C, T
    HA->>HB: H, C, T
    HB->>B: OPEN(H, C, T)
    alt counter replayed or too old
        B-->>HB: result 11
    else bad length or tag
        B-->>HB: result 9
    else authentic
        B->>B: mark counter, decrypt
        B-->>HB: M
    end
```

## 12. Verification and energy flow

Top lane: function and security checks. Bottom lane: how the energy figures are produced.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart LR
    rtl["RTL<br/>hw/se"]
    subgraph V["Function and security"]
        direction LR
        sim["make sim-se<br/>NIST vectors,<br/>17 fault tests"]
        probe["make se-probe<br/>probing check"]
        tvla["make sim-se-tvla<br/>t-test"]
        fc["make sim-se-fault<br/>bit-flip campaign"]
    end
    subgraph E["Energy, sky130"]
        direction LR
        ys["Yosys<br/>map, clock gating"] --> gl["gate-level run<br/>of one KeyGen"] --> sta["OpenSTA<br/>power from SAIF"] --> rep["pqse_energy.py<br/>energy per command"]
        orr["make se-sram-char<br/>OpenRAM + ngspice"] --> tab["sram_table.txt"] --> rep
    end
    rtl --> V
    rtl --> ys
```
