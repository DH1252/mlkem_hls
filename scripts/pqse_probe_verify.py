#!/usr/bin/env python3
"""Exact first-order robust-probing check of the PQSE masked gadgets.

    python3 scripts/pqse_probe_verify.py          (make se-probe; also run by make sim-se)
    python3 scripts/pqse_probe_verify.py --full   larger gadget widths (slower)

Model: the robust probing model with glitches AND transitions (Faust et al.,
TCHES 2018), first order, at the level of the registers of each gadget:
  - every gadget is simulated clock by clock, exactly as its RTL schedules it
    (which register loads what in which clock, when the PRNG word changes)
  - a probe on a register's D input (or on any combinational wire) observes
    every register in that wire's combinational fan-in cone - including a
    register's own value when its load is a data mux (hold path), and every
    data input of every mux in the cone, whatever the select (glitches) -
    in the probed clock AND in the clock before (transitions)
  - the gadget is secure if, for every probe and every clock, the joint
    distribution of what the probe observes is the same for every value of
    the secret, over all values of the shares' masks and the fresh randomness
The distributions are computed exactly, by enumerating all secrets and all
random values (small widths: the gadgets are bit- or word-serial, so their
structure per bit does not depend on the width).

Checked (pqse_mcomp.v, pqse_masked.v, pqse_keccak.v, pqse_io.v, pqse_core.v):
  1 masked Compress adder (two clocks per bit: DOM AND + carry compression),
    m' output shares                                               (mode 0)
  2 the same adder feeding the ok accumulator (compare, DECAPS)      (mode 1)
  3 two ok copies with compression, OKCHK                    (fault detection)
  4 SEL: K = ok ? K' : K-bar with a DOM AND per bit
  5 B2A of the masked CBD (T masked by R, then b1 selects)
  6 Keccak chi on one bit slice of a plane, state in RAM (v4): one RAM per
    share with a registered read port, operands loaded one lane each and
    cleared after the AND, products loaded every clock, write-back; checked in
    the RTL's lane order 0, 2, 4, 1, 3 and in natural order
  7 IO_SEQ: share-wise comparison of two masked m' decodings
  8 the polynomial-RAM read port: precharge between instructions, reads
    share 0 / public / share 1, the registers behind the read bus, and the
    B2A word writer's per-share write registers
Negative controls (the checker must find these leaks, else it is broken):
  N1 the adder of the previous version (one clock per bit, the carry
     recombined combinationally) with its unmasking XOR of the ciphertext bit
  N2 the ok accumulator of the previous version (no compression register)
  N3 chi with the operand muxes of v2
  N4 chi with v3's plane and operand registers but the lanes in natural order
  N5 the read port without the public precharge word (the zero slot of RAM 1
     between share 0 and share 1)
  N6 the two-clock adder with the partial products held after the compress
     clock (a held p01 next to the carry share C1, which contains p10 and so
     the same random bit; found by this check in the first v3 draft)
  N7 chi with the state in RAM but the operands held until reloaded (natural
     order): X of one lane meets Y of the previous lane, the same lane's
     other share
What this does not cover: the netlist after synthesis (a tool may merge or
duplicate logic; check it with a netlist-level tool such as PROLEAD), and
higher orders.
"""
import itertools
import sys
import time
from collections import Counter


class Layout:
    """Bit fields of the packed per-clock state: a probe is a mask over it."""

    def __init__(self, fields):
        self.off, self.width = {}, {}
        o = 0
        for name, w in fields:
            self.off[name] = o
            self.width[name] = w
            o += w
        self.total = o

    def mask(self, names):
        m = 0
        for n in names:
            m |= ((1 << self.width[n]) - 1) << self.off[n]
        return m

    def pack(self, d):
        v = 0
        for n, x in d.items():
            v |= (x & ((1 << self.width[n]) - 1)) << self.off[n]
        return v


class Gadget:
    def __init__(self, name, layout, cones, secrets, randoms, run, expect_secure=True):
        self.name, self.layout = name, layout
        # every register / PRNG output is a probe too (its own value), unless the
        # probe on its D input already observes it (hold path in the cone)
        cones = dict(cones)
        for n in layout.off:
            if n not in cones.get(n, []):
                cones[n + ".Q"] = [n]
        self.cones = cones
        self.secrets, self.randoms, self.run = secrets, randoms, run
        self.expect_secure = expect_secure


def check(g):
    """Returns (number of runs, clocks, list of leaking (probe, clock))."""
    lay = g.layout
    names = list(g.cones)
    masks = [lay.mask(g.cones[p]) for p in names]
    W = lay.total
    ref = None
    leaks = set()
    nrun = 0
    ncyc = None
    for s in g.secrets:
        cnt = None
        for rv in g.randoms():
            tr = g.run(s, rv)
            nrun += 1
            if cnt is None:
                ncyc = len(tr)
                cnt = [[Counter() for _ in masks] for _ in range(ncyc)]
            for t in range(1, ncyc):
                a = tr[t]
                b = tr[t - 1]
                ct = cnt[t]
                for i, m in enumerate(masks):
                    ct[i][((a & m) << W) | (b & m)] += 1
        if ref is None:
            ref = cnt
        else:
            for t in range(1, ncyc):
                for i in range(len(masks)):
                    if cnt[t][i] != ref[t][i]:
                        leaks.add((names[i], t))
    return nrun, ncyc, sorted(leaks, key=lambda x: (x[1], x[0]))


def bits(v, n):
    return [(v >> j) & 1 for j in range(n)]


# =============================== 1, 2, N1, N2: Compress adder ===============================
def adder(K, NT, mode, old=False, held=False):
    """pqse_mcomp.v bit-serial adder (secret x = y0 + y1 mod 2^K, y0 uniform),
    refresh a = (y0 ^ R, R), b = (R', y1 ^ R'), top NT bits are outputs.
    mode 0: output bit shares into G0 / G1; mode 1: into the ok accumulator
    (public ciphertext bits c = 0: nd = NOT(bit)). old: previous version.
    held: the two-clock adder, but with the partial products held after the
    compress clock (the first v3 draft; negative control)."""
    regs = ([f"y0r_{j}" for j in range(K)] + [f"y1r_{j}" for j in range(K)] +
            [f"{r}_{j}" for r in ("A0", "A1", "B0", "B1") for j in range(K)] +
            ["C0", "C1", "p00", "p01", "p10", "p11", "ad0", "ad1", "so0", "so1"] +
            [f"G0_{k}" for k in range(NT)] + [f"G1_{k}" for k in range(NT)] +
            ["ok0", "ok1", "q00", "q01", "q10", "q11"])
    prng = [f"R_{j}" for j in range(K)] + [f"Rp_{j}" for j in range(K)] + ["rb", "rok"]
    lay = Layout([(n, 1) for n in regs + prng])
    top0 = K - NT

    def show(st, w, tr):
        d = dict(st)
        for j in range(K):
            d[f"R_{j}"] = (w[0] >> j) & 1
            d[f"Rp_{j}"] = (w[1] >> j) & 1
        d["rb"], d["rok"] = w[2], w[3]
        tr.append(lay.pack(d))

    def run(x, rv):
        y0, R, Rp, rbs, roks = rv
        y1 = (x - y0) % (1 << K)
        st = {n: 0 for n in regs}
        for j in range(K):
            st[f"y0r_{j}"] = (y0 >> j) & 1
            st[f"y1r_{j}"] = (y1 >> j) & 1
        if old:
            st["q00"] = 1                           # ok = (q00 ^ q01) ^ (q11 ^ q10) = 1
        else:
            st["ok0"] = 1
        # PRNG words: w0 (refresh R, R'), w(i+1) for the AND of bit i, then zeros
        words = [(R, Rp, 0, 0)] + [(0, 0, rbs[i], roks[i]) for i in range(K)] + [(0, 0, 0, 0)]
        tr = []
        show(st, words[0], tr)                      # S_RF
        nx = dict(st)
        for j in range(K):
            Rj, Rpj = (R >> j) & 1, (Rp >> j) & 1
            nx[f"A0_{j}"] = st[f"y0r_{j}"] ^ Rj
            nx[f"A1_{j}"] = Rj
            nx[f"B0_{j}"] = Rpj
            nx[f"B1_{j}"] = st[f"y1r_{j}"] ^ Rpj
        nx["C0"] = nx["C1"] = 0
        st = nx
        wi = 1
        for i in range(K):
            w = words[wi]
            show(st, w, tr)                         # AND clock (old: the only clock)
            a0, a1, b0, b1 = st["A0_0"], st["A1_0"], st["B0_0"], st["B1_0"]
            if old:
                c0 = 0 if i == 0 else st["ad0"] ^ st["p00"] ^ st["p01"]
                c1 = 0 if i == 0 else st["ad1"] ^ st["p11"] ^ st["p10"]
            else:
                c0, c1 = st["C0"], st["C1"]
            P0, P1, Q0, Q1 = a0 ^ b0, a1 ^ b1, a0 ^ c0, a1 ^ c1
            s0, s1 = P0 ^ c0, P1 ^ c1
            nx = dict(st)
            nx["p00"], nx["p01"] = P0 & Q0, (P0 & Q1) ^ w[2]
            nx["p10"], nx["p11"] = (P1 & Q0) ^ w[2], P1 & Q1
            nx["ad0"], nx["ad1"] = a0, a1
            for r in ("A0", "A1", "B0", "B1"):
                for j in range(K):
                    nx[f"{r}_{j}"] = st[f"{r}_{j + 1}"] if j + 1 < K else 0
            top = i >= top0
            if top and mode == 0:
                nx[f"G0_{i - top0}"], nx[f"G1_{i - top0}"] = s0, s1
            ndv = top and mode == 1
            if ndv:
                n0, n1 = 1 ^ s0, s1
                if old:
                    k0 = st["q00"] ^ st["q01"]
                    k1 = st["q11"] ^ st["q10"]
                else:
                    k0, k1 = st["ok0"], st["ok1"]
                nx["q00"], nx["q01"] = k0 & n0, (k0 & n1) ^ w[3]
                nx["q10"], nx["q11"] = (k1 & n0) ^ w[3], k1 & n1
            elif not old:                           # no hold: 0 unless a bit arrives
                nx["q00"] = nx["q01"] = nx["q10"] = nx["q11"] = 0
            st = nx
            wi += 1
            if not old:
                show(st, words[wi], tr)             # compress clock
                nx = dict(st)
                nx["C0"] = st["ad0"] ^ st["p00"] ^ st["p01"]
                nx["C1"] = st["ad1"] ^ st["p11"] ^ st["p10"]
                # the products load every clock: 0 outside the AND clock (no hold)
                if not held:
                    nx["p00"] = nx["p01"] = nx["p10"] = nx["p11"] = 0
                if ndv:
                    nx["ok0"] = st["q00"] ^ st["q01"]
                    nx["ok1"] = st["q11"] ^ st["q10"]
                nx["q00"] = nx["q01"] = nx["q10"] = nx["q11"] = 0
                st = nx
        show(st, words[wi], tr)                     # one idle clock
        # functional check of the model
        if mode == 0:
            got = sum((st[f"G0_{k}"] ^ st[f"G1_{k}"]) << k for k in range(NT))
            assert got == x >> top0, (x, got)
        else:
            if old:
                ok = st["q00"] ^ st["q01"] ^ st["q11"] ^ st["q10"]
            else:
                ok = st["ok0"] ^ st["ok1"]
            assert ok == int((x >> top0) == 0), (x, ok)
        return tr

    def randoms():
        M = 1 << K
        rok_n = NT if mode == 1 else 0
        for y0, R, Rp in itertools.product(range(M), repeat=3):
            for rb in range(1 << K):
                for ro in range(1 << rok_n):
                    rbs = bits(rb, K)
                    roks = [0] * top0 + bits(ro, rok_n) if mode == 1 else [0] * K
                    yield (y0, R, Rp, rbs, roks)

    # cones (the registers each wire / D input depends on)
    cones = {}
    for j in range(K):
        nxt = lambda r: [f"{r}_{j + 1}"] if j + 1 < K else []
        cones[f"A0_{j}"] = [f"y0r_{j}", f"R_{j}", f"A0_{j}"] + nxt("A0")
        cones[f"A1_{j}"] = [f"R_{j}", f"A1_{j}"] + nxt("A1")
        cones[f"B0_{j}"] = [f"Rp_{j}", f"B0_{j}"] + nxt("B0")
        cones[f"B1_{j}"] = [f"y1r_{j}", f"Rp_{j}", f"B1_{j}"] + nxt("B1")
    if old:
        c0 = ["ad0", "p00", "p01"]                  # the carry, combinational
        c1 = ["ad1", "p11", "p10"]
    else:
        c0, c1 = ["C0"], ["C1"]
        cones["C0"] = ["ad0", "p00", "p01", "C0"]
        cones["C1"] = ["ad1", "p11", "p10", "C1"]
    # previous version: the products are enabled registers (hold path); now
    # they load every clock (product in the AND clock, else 0): no hold path
    hp = (lambda n: [n]) if (old or held) else (lambda n: [])
    cones["p00"] = ["A0_0", "B0_0"] + c0 + hp("p00")
    cones["p01"] = ["A0_0", "B0_0", "A1_0"] + c1 + ["rb"] + hp("p01")
    cones["p10"] = ["A1_0", "B1_0", "A0_0"] + c0 + ["rb"] + hp("p10")
    cones["p11"] = ["A1_0", "B1_0"] + c1 + hp("p11")
    cones["ad0"] = ["A0_0", "ad0"]
    cones["ad1"] = ["A1_0", "ad1"]
    sum0 = ["A0_0", "B0_0"] + c0
    sum1 = ["A1_0", "B1_0"] + c1
    cones["sum0"], cones["sum1"] = sum0, sum1
    if old:
        cones["ct_bit"] = sum0 + sum1               # WL / WH <= sum0 ^ sum1 (any mode)
    else:
        cones["so0"] = sum0 + ["so0"]
        cones["so1"] = sum1 + ["so1"]
        cones["ct_bit"] = ["so0", "so1"]            # mode 2 only loads so0 / so1
    for k in range(NT):
        cones[f"G0_{k}"] = sum0 + [f"G0_{k}"]
        cones[f"G1_{k}"] = sum1 + [f"G1_{k}"]
    if mode == 1:
        if old:                                     # enabled registers (hold path)
            k0, k1 = ["q00", "q01"], ["q11", "q10"]
            cones["q00"] = k0 + sum0
            cones["q01"] = k0 + sum1 + ["rok"]
            cones["q10"] = k1 + sum0 + ["rok"]
            cones["q11"] = k1 + sum1
        else:                                       # load every clock: no hold path
            cones["q00"] = ["ok0"] + sum0
            cones["q01"] = ["ok0"] + sum1 + ["rok"]
            cones["q10"] = ["ok1"] + sum0 + ["rok"]
            cones["q11"] = ["ok1"] + sum1
            cones["ok0"] = ["q00", "q01", "ok0"]
            cones["ok1"] = ["q11", "q10", "ok1"]
    for n in prng:
        cones[n] = [n]
    for j in range(K):
        cones[f"y0r_{j}"] = [f"y0r_{j}"]
        cones[f"y1r_{j}"] = [f"y1r_{j}"]
    name = ("previous adder" if old else
            "adder with held partial products" if held else "Compress adder") + \
           (f", mode {mode} (" + ("m' shares" if mode == 0 else "ok accumulator") + f"), K = {K}")
    return Gadget(name, lay, cones, list(range(1 << K)), randoms, run,
                  expect_secure=not (old or held))


# =============================== 3: ok copies + OKCHK ===============================
def ok_copies(n):
    regs = ["n0", "n1", "ok0", "ok1", "okb0", "okb1", "q00", "q01", "q10", "q11",
            "t00", "t01", "t10", "t11", "ce0", "ce1"]
    lay = Layout([(x, 1) for x in regs + ["rok", "rokb"]])

    def run(nd, rv):
        msk, ra, rb = rv
        st = {x: 0 for x in regs}
        st["ok0"] = st["okb0"] = 1
        tr = []
        words = [(ra[k], rb[k]) for k in range(n)] + [(0, 0)]

        def show(w):
            d = dict(st)
            d["rok"], d["rokb"] = w
            tr.append(lay.pack(d))
        show(words[0])
        prods = ["q00", "q01", "q10", "q11", "t00", "t01", "t10", "t11"]
        for k in range(n):
            st["n0"] = ((nd >> k) & 1) ^ ((msk >> k) & 1)   # the nd shares arrive
            st["n1"] = (msk >> k) & 1
            w = words[k]
            show(w)                                          # AND clock
            nx = dict(st)
            for (a0, a1, r, p) in (("ok0", "ok1", w[0], "q"), ("okb0", "okb1", w[1], "t")):
                nx[p + "00"] = st[a0] & st["n0"]
                nx[p + "01"] = (st[a0] & st["n1"]) ^ r
                nx[p + "10"] = (st[a1] & st["n0"]) ^ r
                nx[p + "11"] = st[a1] & st["n1"]
            st.update(nx)
            show(words[k + 1])                               # compress clock
            nx = dict(st)
            nx["ok0"], nx["ok1"] = st["q00"] ^ st["q01"], st["q11"] ^ st["q10"]
            nx["okb0"], nx["okb1"] = st["t00"] ^ st["t01"], st["t11"] ^ st["t10"]
            for p in prods:                                  # no hold: 0 without a bit
                nx[p] = 0
            st.update(nx)
        show(words[n])                                       # OKCHK stage 1
        ce0, ce1 = st["ok0"] ^ st["okb0"], st["ok1"] ^ st["okb1"]
        st["ce0"], st["ce1"] = ce0, ce1
        show(words[n])                                       # stage 2: fault = ce0 ^ ce1
        show(words[n])
        allok = int(nd == (1 << n) - 1)
        assert st["ok0"] ^ st["ok1"] == allok and st["okb0"] ^ st["okb1"] == allok
        assert ce0 ^ ce1 == 0
        return tr

    def randoms():
        for msk in range(1 << n):
            for ra in range(1 << n):
                for rb in range(1 << n):
                    yield (msk, bits(ra, n), bits(rb, n))

    # the partial-product registers load every clock (no hold path in their cones)
    cones = {
        "q00": ["ok0", "n0"], "q01": ["ok0", "n1", "rok"],
        "q10": ["ok1", "n0", "rok"], "q11": ["ok1", "n1"],
        "t00": ["okb0", "n0"], "t01": ["okb0", "n1", "rokb"],
        "t10": ["okb1", "n0", "rokb"], "t11": ["okb1", "n1"],
        "ok0": ["q00", "q01", "ok0"], "ok1": ["q11", "q10", "ok1"],
        "okb0": ["t00", "t01", "okb0"], "okb1": ["t11", "t10", "okb1"],
        "ce0": ["ok0", "okb0", "ce0"], "ce1": ["ok1", "okb1", "ce1"],
        "fault": ["ce0", "ce1"], "n0": ["n0"], "n1": ["n1"], "rok": ["rok"], "rokb": ["rokb"],
    }
    return Gadget(f"two ok copies + OKCHK, {n} comparison bits", lay, cones,
                  list(range(1 << n)), randoms, run)


# =============================== 4: SEL ===============================
def sel(nb=2):
    regs = (["ok0", "ok1", "s00", "s01", "s10", "s11"] +
            [f"{r}_{b}" for r in ("srd0", "srd1", "D0", "D1", "kb0", "kb1", "O0", "O1")
             for b in range(nb)])
    lay = Layout([(x, 1) for x in regs + ["rsel"]])

    def run(sec, rv):
        ok, kp, kbar = sec
        okm, mp, mb, rs = rv
        st = {x: 0 for x in regs}
        st["ok0"], st["ok1"] = ok ^ okm, okm
        tr = []
        words = list(rs) + [0]

        def show(r):
            d = dict(st)
            d["rsel"] = r
            tr.append(lay.pack(d))

        def setv(name, v0, v1):
            for b in range(nb):
                st[f"{name}0_{b}"] = (v0 >> b) & 1
                st[f"{name}1_{b}"] = (v1 >> b) & 1
        show(words[0])                                  # sph 0: read K'
        setv("srd", kp ^ mp, mp)                        # K' shares on the seed RAM outputs
        show(words[0])                                  # sph 1: D := K'
        for b in range(nb):
            st[f"D0_{b}"], st[f"D1_{b}"] = st[f"srd0_{b}"], st[f"srd1_{b}"]
        setv("srd", kbar ^ mb, mb)                      # K-bar shares
        show(words[0])                                  # sph 2: D ^= K-bar, kb := K-bar
        for b in range(nb):
            st[f"D0_{b}"] ^= st[f"srd0_{b}"]
            st[f"D1_{b}"] ^= st[f"srd1_{b}"]
            st[f"kb0_{b}"], st[f"kb1_{b}"] = st[f"srd0_{b}"], st[f"srd1_{b}"]
        for sb in range(nb + 1):                        # sph 3
            r = words[sb]
            show(r)
            nx = dict(st)
            if sb < nb:
                d0, d1 = st[f"D0_{sb}"], st[f"D1_{sb}"]
                nx["s00"], nx["s01"] = st["ok0"] & d0, (st["ok0"] & d1) ^ r
                nx["s10"], nx["s11"] = (st["ok1"] & d0) ^ r, st["ok1"] & d1
            if sb >= 1:
                o0 = st[f"kb0_{sb - 1}"] ^ st["s00"] ^ st["s01"]
                o1 = st[f"kb1_{sb - 1}"] ^ st["s11"] ^ st["s10"]
                for b in range(nb - 1):
                    nx[f"O0_{b}"], nx[f"O1_{b}"] = st[f"O0_{b + 1}"], st[f"O1_{b + 1}"]
                nx[f"O0_{nb - 1}"], nx[f"O1_{nb - 1}"] = o0, o1
            st = nx
        show(words[nb])                                 # sph 4: write
        show(words[nb])
        k = sum((st[f"O0_{b}"] ^ st[f"O1_{b}"]) << b for b in range(nb))
        assert k == (kp if ok else kbar), (sec, k)
        return tr

    def randoms():
        M = 1 << nb
        for okm in range(2):
            for mp in range(M):
                for mb in range(M):
                    for rs in range(M):
                        yield (okm, mp, mb, bits(rs, nb))

    D0s = [f"D0_{b}" for b in range(nb)]
    D1s = [f"D1_{b}" for b in range(nb)]
    cones = {"s00": ["ok0", "s00"] + D0s, "s01": ["ok0", "rsel", "s01"] + D1s,
             "s10": ["ok1", "rsel", "s10"] + D0s, "s11": ["ok1", "s11"] + D1s,
             "ok0": ["ok0"], "ok1": ["ok1"], "rsel": ["rsel"]}
    for b in range(nb):
        cones[f"D0_{b}"] = [f"D0_{b}", f"srd0_{b}"]
        cones[f"D1_{b}"] = [f"D1_{b}", f"srd1_{b}"]
        cones[f"kb0_{b}"] = [f"kb0_{b}", f"srd0_{b}"]
        cones[f"kb1_{b}"] = [f"kb1_{b}", f"srd1_{b}"]
        cones[f"srd0_{b}"] = [f"srd0_{b}"]
        cones[f"srd1_{b}"] = [f"srd1_{b}"]
        nxt0 = [f"O0_{b + 1}"] if b + 1 < nb else []
        nxt1 = [f"O1_{b + 1}"] if b + 1 < nb else []
        cones[f"O0_{b}"] = ([f"kb0_{x}" for x in range(nb)] + ["s00", "s01", f"O0_{b}"] + nxt0)
        cones[f"O1_{b}"] = ([f"kb1_{x}" for x in range(nb)] + ["s11", "s10", f"O1_{b}"] + nxt1)
    secrets = [(ok, kp, kb) for ok in range(2) for kp in range(1 << nb) for kb in range(1 << nb)]
    return Gadget(f"SEL (K = ok ? K' : K-bar), {nb}-bit keys", lay, cones, secrets, randoms, run)


# =============================== 5: B2A (masked CBD) ===============================
def b2a(q=7):
    W3 = q.bit_length()
    regs = ["L0_0", "L0_1", "L1_0", "L1_1", "b1d"]
    vals = ["T", "Rd", "vd", "acc0", "acc1", "wr0", "wr1", "Rq"]
    lay = Layout([(x, 1) for x in regs] + [(x, W3) for x in vals])
    wts = [1, q - 1]                                    # CBD weights +1, -1

    def run(sec, rv):
        m, R = rv                                       # share-1 masks of the 2 bits, R per bit
        st = {x: 0 for x in regs + vals}
        for j in range(2):
            bj, mj = (sec >> j) & 1, (m >> j) & 1
            st[f"L0_{j}"], st[f"L1_{j}"] = bj ^ mj, mj
        tr = []
        prq = [R[0], R[1], 0, 0, 0]
        s1 = None
        for c in range(4):
            st["Rq"] = prq[c]
            tr.append(lay.pack(st))
            nx = dict(st)
            if s1 is not None:                          # stage 1 of the previous bit
                first, last = s1
                A0v = (-st["T"]) % q if st["b1d"] else st["T"]
                A1v = (st["vd"] - st["Rd"]) % q if st["b1d"] else st["Rd"]
                a0 = (0 if first else st["acc0"]) + A0v
                a1 = (0 if first else st["acc1"]) + A1v
                nx["acc0"], nx["acc1"] = a0 % q, a1 % q
                if last:
                    nx["wr0"], nx["wr1"] = a0 % q, a1 % q
                s1 = None
            if c < 2:                                   # stage 0: issue bit c
                v = wts[c]
                nx["T"] = ((v if st[f"L0_{c}"] else 0) - st["Rq"]) % q
                nx["b1d"] = st[f"L1_{c}"]
                nx["Rd"] = st["Rq"]
                nx["vd"] = v
                s1 = (c == 0, c == 1)
            st = nx
        val = (st["wr0"] + st["wr1"]) % q
        assert val == ((sec & 1) - ((sec >> 1) & 1)) % q, (sec, val)
        return tr

    def randoms():
        for m in range(4):
            for r0 in range(q):
                for r1 in range(q):
                    yield (m, (r0, r1))

    cones = {"T": ["L0_0", "L0_1", "Rq", "T"], "b1d": ["L1_0", "L1_1", "b1d"],
             "Rd": ["Rq", "Rd"], "vd": ["vd"], "acc0": ["acc0", "b1d", "T"],
             "acc1": ["acc1", "b1d", "vd", "Rd"], "wr0": ["acc0", "b1d", "T", "wr0"],
             "wr1": ["acc1", "b1d", "vd", "Rd", "wr1"], "Rq": ["Rq"],
             "L0_0": ["L0_0"], "L0_1": ["L0_1"], "L1_0": ["L1_0"], "L1_1": ["L1_1"]}
    return Gadget(f"B2A of the masked CBD (2 bits, mod {q})", lay, cones, list(range(4)), randoms, run)


# =============================== 6, N3, N4: Keccak chi slice ===============================
def chi(variant):
    """variant: 'new' (operand registers, order 0 2 4 1 3), 'mux' (previous: operand
    muxes, order 0..4), 'natural' (operand registers, order 0..4)."""
    regs = ([f"A0_{x}" for x in range(5)] + [f"A1_{x}" for x in range(5)] +
            [f"P0_{x}" for x in range(5)] + [f"P1_{x}" for x in range(5)] +
            [f"C0_{x}" for x in range(5)] + [f"C1_{x}" for x in range(5)] +
            ["X0r", "X1r", "Y0r", "Y1r", "d00", "d01", "d10", "d11"])
    lay = Layout([(x, 1) for x in regs + ["rr"]])
    order = [0, 2, 4, 1, 3] if variant == "new" else [0, 1, 2, 3, 4]
    opreg = variant != "mux"
    ld1 = variant == "new"          # operand / product registers load every clock (no hold)

    def run(a, rv):
        m, r = rv
        st = {x: 0 for x in regs}
        for x in range(5):
            st[f"A0_{x}"], st[f"A1_{x}"] = ((a >> x) & 1) ^ ((m >> x) & 1), (m >> x) & 1
        tr = []
        # schedule: operand load at cs 5 + k, DOM at 6 + k, write-back at 7 + k
        # (previous version: DOM from the muxes at cs 5 + k, write-back at 6 + k)
        dom0 = 6 if opreg else 5
        ncs = dom0 + 6 + 1
        for cs in range(ncs):
            k = cs - dom0                                # the DOM being done this clock
            st_r = r[min(max(k, 0), 5)] if k < 5 else 0  # PRNG: taken at each DOM
            d = dict(st)
            d["rr"] = st_r
            tr.append(lay.pack(d))
            nx = dict(st)
            if cs <= 4:
                nx[f"P0_{cs}"], nx[f"P1_{cs}"] = st[f"A0_{cs}"], st[f"A1_{cs}"]
            if opreg and 5 <= cs <= 9:
                x = order[cs - 5]
                nx["X0r"] = 1 ^ st[f"P0_{(x + 1) % 5}"]
                nx["Y0r"] = st[f"P0_{(x + 2) % 5}"]
                nx["X1r"] = st[f"P1_{(x + 1) % 5}"]
                nx["Y1r"] = st[f"P1_{(x + 2) % 5}"]
            elif ld1:                                    # load every clock: 0 when unused
                nx["X0r"] = nx["Y0r"] = nx["X1r"] = nx["Y1r"] = 0
            if not 0 <= k <= 4 and ld1:
                nx["d00"] = nx["d01"] = nx["d10"] = nx["d11"] = 0
            if 0 <= k <= 4:
                x = order[k]
                if opreg:
                    X0, Y0, X1, Y1 = st["X0r"], st["Y0r"], st["X1r"], st["Y1r"]
                else:
                    X0, Y0 = 1 ^ st[f"P0_{(x + 1) % 5}"], st[f"P0_{(x + 2) % 5}"]
                    X1, Y1 = st[f"P1_{(x + 1) % 5}"], st[f"P1_{(x + 2) % 5}"]
                nx["d00"], nx["d01"] = X0 & Y0, (X0 & Y1) ^ st_r
                nx["d10"], nx["d11"] = (X1 & Y0) ^ st_r, X1 & Y1
            kw = k - 1
            if 0 <= kw <= 4:
                x = order[kw]
                c0 = st[f"P0_{x}"] ^ st["d00"] ^ st["d01"]
                c1 = st[f"P1_{x}"] ^ st["d11"] ^ st["d10"]
                nx[f"A0_{x}"], nx[f"A1_{x}"] = c0, c1
                nx[f"C0_{x}"] ^= c0
                nx[f"C1_{x}"] ^= c1
            st = nx
        for x in range(5):
            want = ((a >> x) & 1) ^ ((1 ^ ((a >> ((x + 1) % 5)) & 1)) & ((a >> ((x + 2) % 5)) & 1))
            assert st[f"A0_{x}"] ^ st[f"A1_{x}"] == want, (a, x)
        return tr

    def randoms():
        for m in range(32):
            for r in range(32):
                yield (m, bits(r, 5))

    P0s = [f"P0_{x}" for x in range(5)]
    P1s = [f"P1_{x}" for x in range(5)]
    A0s = [f"A0_{x}" for x in range(5)]
    A1s = [f"A1_{x}" for x in range(5)]
    cones = {}
    for x in range(5):
        cones[f"P0_{x}"] = A0s + [f"P0_{x}"]
        cones[f"P1_{x}"] = A1s + [f"P1_{x}"]
        cones[f"A0_{x}"] = P0s + ["d00", "d01", f"A0_{x}"]
        cones[f"A1_{x}"] = P1s + ["d11", "d10", f"A1_{x}"]
        cones[f"C0_{x}"] = P0s + ["d00", "d01", f"C0_{x}"]
        cones[f"C1_{x}"] = P1s + ["d11", "d10", f"C1_{x}"]
    if opreg:
        hp = (lambda n: []) if ld1 else (lambda n: [n])   # hold path of an enabled register
        cones["X0r"] = P0s + hp("X0r")
        cones["Y0r"] = P0s + hp("Y0r")
        cones["X1r"] = P1s + hp("X1r")
        cones["Y1r"] = P1s + hp("Y1r")
        cones["d00"] = ["X0r", "Y0r"] + hp("d00")
        cones["d01"] = ["X0r", "Y1r", "rr"] + hp("d01")
        cones["d10"] = ["X1r", "Y0r", "rr"] + hp("d10")
        cones["d11"] = ["X1r", "Y1r"] + hp("d11")
    else:
        cones["d00"] = P0s + ["d00"]
        cones["d01"] = P0s + P1s + ["rr", "d01"]
        cones["d10"] = P1s + P0s + ["rr", "d10"]
        cones["d11"] = P1s + ["d11"]
    cones["rr"] = ["rr"]
    name = {"new": "v3 chi slice (plane register, operand registers, lanes 0 2 4 1 3)",
            "mux": "previous chi (DOM operands from the plane muxes)",
            "natural": "chi with operand registers but lanes in order 0 1 2 3 4"}[variant]
    return Gadget(name, lay, cones, list(range(32)), randoms, run, expect_secure=(variant == "new"))


# =============================== 6b, N7: Keccak chi, state in RAM (v4) ===============================
def chi_ram(order, clear=True):
    """pqse_keccak.v (v4): one bit slice of a plane; each share in its own RAM
    (B = chi input, A = output words), one registered read port per RAM.
    Per lane x (4 clocks): c0 read B[x+1]; c1 X <= ~B0 / B1, read B[x+2];
    c2 Y <= B, read B[x]; c3 DOM -> d, X cleared; next c0: A[x] <= B[x] ^ d.
    clear = False: X and Y keep their values until reloaded (negative control)."""
    regs = ([f"B0_{x}" for x in range(5)] + [f"B1_{x}" for x in range(5)] +
            [f"A0_{x}" for x in range(5)] + [f"A1_{x}" for x in range(5)] +
            ["q0", "q1", "X0r", "X1r", "Y0r", "Y1r", "d00", "d01", "d10", "d11"])
    lay = Layout([(n, 1) for n in regs + ["rr"]])

    def run(a, rv):
        m, r = rv
        st = {n: 0 for n in regs}
        for x in range(5):
            st[f"B0_{x}"] = ((a >> x) & 1) ^ ((m >> x) & 1)
            st[f"B1_{x}"] = (m >> x) & 1
        tr = []
        wb = None
        slots = [(k, c) for k in range(5) for c in range(4)] + [(5, 0), (5, 1)]
        for k, c in slots:
            rr = r[k] if k < 5 else 0                    # the PRNG word the next AND takes
            d = dict(st)
            d["rr"] = rr
            tr.append(lay.pack(d))
            nx = dict(st)
            if wb is not None:                           # write-back of the previous lane
                nx[f"A0_{wb}"] = st["q0"] ^ st["d00"] ^ st["d01"]
                nx[f"A1_{wb}"] = st["q1"] ^ st["d11"] ^ st["d10"]
                wb = None
            nx["d00"] = nx["d01"] = nx["d10"] = nx["d11"] = 0   # products: load every clock
            if clear:
                nx["Y0r"] = nx["Y1r"] = 0                # Y: load every clock
            if k < 5:
                x = order[k]
                rd = None
                if c == 0:
                    rd = (x + 1) % 5
                elif c == 1:
                    nx["X0r"], nx["X1r"] = 1 ^ st["q0"], st["q1"]
                    rd = (x + 2) % 5
                elif c == 2:
                    nx["Y0r"], nx["Y1r"] = st["q0"], st["q1"]
                    rd = x
                else:
                    X0, X1, Y0, Y1 = st["X0r"], st["X1r"], st["Y0r"], st["Y1r"]
                    nx["d00"], nx["d01"] = X0 & Y0, (X0 & Y1) ^ rr
                    nx["d10"], nx["d11"] = (X1 & Y0) ^ rr, X1 & Y1
                    if clear:
                        nx["X0r"] = nx["X1r"] = 0
                    wb = x
                if rd is not None:                       # registered RAM read
                    nx["q0"], nx["q1"] = st[f"B0_{rd}"], st[f"B1_{rd}"]
            st = nx
        for x in range(5):
            want = ((a >> x) & 1) ^ ((1 ^ ((a >> ((x + 1) % 5)) & 1)) & ((a >> ((x + 2) % 5)) & 1))
            assert st[f"A0_{x}"] ^ st[f"A1_{x}"] == want, (a, x)
        return tr

    def randoms():
        for m in range(32):
            for r in range(32):
                yield (m, bits(r, 5))

    B0s, B1s = [f"B0_{x}" for x in range(5)], [f"B1_{x}" for x in range(5)]
    A0s, A1s = [f"A0_{x}" for x in range(5)], [f"A1_{x}" for x in range(5)]
    cones = {
        "q0": B0s + A0s + ["q0"],                  # RAM 0: its read mux sees every word
        "q1": B1s + A1s + ["q1"],
        "X0r": ["q0", "X0r"], "X1r": ["q1", "X1r"],    # loaded at c1, held at c2
        "Y0r": ["q0"] + ([] if clear else ["Y0r"]),
        "Y1r": ["q1"] + ([] if clear else ["Y1r"]),
        "d00": ["X0r", "Y0r"], "d01": ["X0r", "Y1r", "rr"],
        "d10": ["X1r", "Y0r", "rr"], "d11": ["X1r", "Y1r"],
        "rr": ["rr"],
    }
    for x in range(5):                             # write data bus (+ the word itself)
        cones[f"A0_{x}"] = ["q0", "d00", "d01", f"A0_{x}"]
        cones[f"A1_{x}"] = ["q1", "d11", "d10", f"A1_{x}"]
    if clear:
        name = "Keccak chi, state in RAM (operands cleared after the AND, lanes " + \
               " ".join(map(str, order)) + ")"
    else:
        name = "chi in RAM with operands held until reloaded, lanes " + " ".join(map(str, order))
    return Gadget(name, lay, cones, list(range(32)), randoms, run, expect_secure=clear)


# =============================== 7: IO_SEQ ===============================
def seq(nb=2):
    regs = ["srd0", "srd1", "sa0", "sa1", "sd0", "sd1"]
    lay = Layout([(x, nb) for x in regs])

    def run(v, rv):
        e1, f1 = rv
        st = {x: 0 for x in regs}
        tr = []
        for sq in range(6):
            tr.append(lay.pack(st))
            nx = dict(st)
            if sq == 0:                                   # read e
                nx["srd0"], nx["srd1"] = v ^ e1, e1
            if sq == 1:                                   # e captured, read e2
                nx["sa0"], nx["sa1"] = st["srd0"], st["srd1"]
                nx["srd0"], nx["srd1"] = v ^ f1, f1
            if sq == 2:                                   # share-wise differences
                nx["sd0"], nx["sd1"] = st["sa0"] ^ st["srd0"], st["sa1"] ^ st["srd1"]
            st = nx
        assert st["sd0"] ^ st["sd1"] == 0
        return tr

    def randoms():
        M = 1 << nb
        for e1 in range(M):
            for f1 in range(M):
                yield (e1, f1)

    cones = {"srd0": ["srd0"], "srd1": ["srd1"], "sa0": ["srd0", "sa0"], "sa1": ["srd1", "sa1"],
             "sd0": ["sa0", "srd0", "sd0"], "sd1": ["sa1", "srd1", "sd1"], "fault": ["sd0", "sd1"]}
    return Gadget("IO_SEQ (two masked m' decodings compared share-wise)", lay, cones,
                  list(range(1 << nb)), randoms, run)


# =============================== 8, N5: RAM read port + word writer ===============================
def readport(kind, old=False, nw=2, wb=2):
    """The polynomial-RAM read port (two RAM output registers pr0 / pr1 behind one
    read mux, pqse_core.v) and the registers an engine loads from it.
    kind 'mcomp':  pqse_mcomp.v reads share 0, a public word, (idle), share 1
                   into X0w -> Z0 and X1w
    kind 'writer': the B2A word writer of pqse_masked.v (o0, o1, wd0, wd1)
    Two instructions handle the same nw words, the second in reverse order (so
    its first word is the first one's last), with the sequencer's precharge
    reads between them. Secret: the nw coefficient values (shares mod 2^wb)."""
    M = 1 << wb
    PUB = M - 1                                         # a public word (S_T word 0)
    regs = ["pr0", "pr1", "X0w", "Z0", "X1w", "o0", "o1", "wd0", "wd1"]
    lay = Layout([(x, wb) for x in regs] + [("sel", 1)])

    def run(sec, rv):
        xs = [(sec >> (wb * w)) & (M - 1) for w in range(nw)]
        x0 = list(rv)
        x1 = [(xs[w] - x0[w]) % M for w in range(nw)]
        st = {x: 0 for x in regs}
        st["sel"] = 0
        tr = []

        def clock(read=None, ld=()):
            # read = (ram, value): that RAM's output register and sel change at the
            # end of this clock; ld: register loads (from the read bus or not)
            tr.append(lay.pack(st))
            nx = dict(st)
            bus = st["pr1"] if st["sel"] else st["pr0"]
            for op in ld:
                if op in ("X0w", "X1w", "o0", "o1"):
                    nx[op] = bus
                elif op == "Z0":                         # Z0 <= X0w, X0w <= 0
                    nx["Z0"], nx["X0w"] = st["X0w"], 0
                elif op == "wd0":                        # wd0 <= o0 (+ wr0), o0 <= 0
                    nx["wd0"], nx["o0"] = st["o0"], 0
                elif op == "wd1":
                    nx["wd1"], nx["o1"] = st["o1"], 0
                elif op == "wd0clr":
                    nx["wd0"] = 0
                elif op == "wd1clr":
                    nx["wd1"] = 0
                elif op == "idle":                       # mcomp idle: bus registers cleared
                    nx["X0w"] = nx["Z0"] = nx["X1w"] = 0
                elif op == "wd_old0":                    # previous writer: no clears
                    nx["wd0"] = st["o0"]
                elif op == "wd_old1":
                    nx["wd1"] = st["o1"]
            if read is not None:
                ram, v = read
                nx["pr1" if ram else "pr0"] = v
                nx["sel"] = ram
            st.update(nx)

        for order in (list(range(nw)), list(reversed(range(nw)))):
            if not old:                                  # instruction boundary precharge
                clock(read=(1, 0))                       # Q_FETCH: RAM 1 zero slot
                clock(read=(0, PUB))                     # Q_PG: RAM 0 public word
            for w in order:
                if kind == "mcomp" and not old:
                    clock(read=(0, x0[w]))               # S_R0: share 0 word
                    clock(read=(0, PUB), ld=("X0w",))    # S_R1: public word of RAM 0
                    clock(ld=("Z0",))                    # S_R2: X0w -> Z0, X0w := 0
                    clock(read=(1, x1[w]))               # S_RD1: share 1 word
                    clock(ld=("X1w",))                   # S_R3
                elif kind == "mcomp":                    # previous version
                    clock(read=(0, x0[w]))
                    clock(read=(1, 0), ld=("X0w",))      # zero slot of RAM 1
                    clock(read=(1, x1[w]))
                    clock(ld=("X1w",))
                elif not old:                            # writer
                    clock(read=(0, x0[w]))               # 0
                    clock(read=(0, PUB), ld=("o0",))     # 1
                    clock(ld=("wd0",))                   # 2
                    clock(read=(1, x1[w]))               # 3
                    clock(ld=("o1", "wd0clr"))           # 4: write share 0
                    clock(ld=("wd1",))                   # 5
                    clock(ld=("wd1clr",))                # 6: write share 1
                else:                                    # previous writer
                    clock(read=(0, x0[w]))
                    clock(read=(1, 0), ld=("o0",))
                    clock(read=(1, x1[w]))
                    clock(ld=("o1",))
                    clock(ld=("wd_old0",))
                    clock(ld=("wd_old1",))
            if kind == "mcomp" and not old:
                clock(ld=("idle",))
        clock()
        return tr

    def randoms():
        for x0 in itertools.product(range(M), repeat=nw):
            yield x0

    bus = ["pr0", "pr1", "sel"]
    if kind == "mcomp":
        cones = {"bus": bus, "X0w": bus + ["X0w"], "X1w": bus + ["X1w"]}
        if not old:
            cones["Z0"] = ["X0w", "Z0"]
    else:
        cones = {"bus": bus, "o0": bus + ["o0"], "o1": bus + ["o1"]}
        if old:                                         # one write-data mux over both results
            cones["wdata"] = ["o0", "o1", "wd0", "wd1"]
        else:
            cones["wd0"] = ["o0", "wd0"]
            cones["wd1"] = ["o1", "wd1"]
            cones["wdata"] = ["wd0", "wd1"]
    what = "Compress engine" if kind == "mcomp" else "B2A word writer"
    name = (f"previous RAM read port + {what} (zero slot of RAM 1 between the shares)" if old else
            f"RAM read port (precharge, share 0 / public / share 1) + {what} registers")
    return Gadget(name, lay, cones, list(range(1 << (wb * nw))), randoms, run, expect_secure=not old)


def main():
    full = "--full" in sys.argv
    gadgets = [
        adder(4 if full else 3, 2, 0),
        adder(3 if full else 2, 2, 1),
        ok_copies(4 if full else 3),
        sel(),
        b2a(),
        chi_ram([0, 2, 4, 1, 3]),
        chi_ram([0, 1, 2, 3, 4]),        # the clearing alone already makes any order safe
        seq(),
        readport("mcomp"),
        readport("writer"),
        adder(3, 2, 0, old=True),
        adder(2, 2, 1, old=True),
        adder(3, 2, 0, held=True),
        adder(2, 2, 1, held=True),
        chi("mux"),
        chi("natural"),
        chi_ram([0, 1, 2, 3, 4], clear=False),
        readport("mcomp", old=True),
        readport("writer", old=True),
    ]
    for g in gadgets:
        if not g.expect_secure:
            # a known leak shows between two secrets that differ everywhere: two are enough
            g.secrets = [g.secrets[0], g.secrets[-1]]
    bad = 0
    t_all = time.time()
    for g in gadgets:
        t0 = time.time()
        nrun, ncyc, leaks = check(g)
        dt = time.time() - t0
        info = f"{len(g.cones)} probes x {ncyc} clocks, {nrun} runs, {dt:.1f} s"
        if g.expect_secure:
            if leaks:
                bad += 1
                print(f"[FAIL] {g.name}: {len(leaks)} leaking probe/clock pairs ({info})")
                for p, t in leaks[:12]:
                    print(f"         probe {p} at clock {t}")
            else:
                print(f"[PASS] {g.name}: secure, glitches + transitions ({info})")
        else:
            if leaks:
                p, t = leaks[0]
                print(f"[PASS] negative control - {g.name}: leak found as expected "
                      f"(probe {p} at clock {t}, {len(leaks)} in all)")
            else:
                bad += 1
                print(f"[FAIL] negative control - {g.name}: the known leak was NOT found "
                      f"(the checker is broken) ({info})")
    print(f"({time.time() - t_all:.0f} s)")
    print("PROBING CHECK PASSED" if bad == 0 else f"PROBING CHECK FAILED: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
