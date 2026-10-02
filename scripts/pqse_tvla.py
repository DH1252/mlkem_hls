#!/usr/bin/env python3
"""TVLA (fixed-vs-random, first order) inputs and report for the PQSE masked Decaps.

    python3 scripts/pqse_tvla.py gen N OUT [--vectors hw/sim/vectors] [--seed 1]
        Self-checks a small ML-KEM-768 model (FIPS 203) against the NIST Encaps
        vector, then writes OUT: the line "N", then N lines "class c-bytes" with
        ciphertexts for the ek of the NIST KeyGen vector (kg_dk):
            class 0: K-PKE.Encrypt(ek, m_fixed, random coins)
            class 1: K-PKE.Encrypt(ek, random m, random coins)
        in random order. The coins are random (not G(m || H(ek))), so the
        ciphertexts are random in both classes and Decaps takes its implicit-
        rejection path; only the secret intermediates (m', K', r', the masked
        re-encryption and comparison) differ between the classes.

    python3 scripts/pqse_tvla.py report TVLA_T [--png out.png]
        Summarizes tvla_t.txt (from hw/sim/tb_pqse_tvla.sv): max |t|, the samples
        above the 4.5 threshold grouped by microcode instruction (pc), and a
        plot of t over time when matplotlib is installed. It also prints how many
        crossings of 4.5 chance alone produces: with ~176,000 samples a leak-free
        design still crosses it about twice at 200 traces.

    python3 scripts/pqse_tvla.py confirm RUN1/tvla_t.txt RUN2/tvla_t.txt
        TVLA's two-set rule: a leak is confirmed only where two independent runs
        (different SEED) both exceed 4.5 at the same sample with the same sign.

    python3 scripts/pqse_tvla.py board TRACES TVLA_IN [--out t.txt] [--align W]
        The same test on real measurements: TRACES holds the oscilloscope
        captures of the Decaps runs made by quartus/jtag/pqse_tvla_capture.tcl
        (one trace per Decaps, triggered by the trigger pin, in capture order):
        .npy = an N x S array (numpy), .csv / .txt = one trace per line. TVLA_IN
        is the file the capture used (it gives each trace's class). Writes the t
        values in the tvla_t.txt format (pc column 0: a scope does not know the
        instruction) and reports them as above; 'confirm' works on two such
        files (captures from two --seed sets). --align W re-aligns every trace
        to the mean of the first traces by cross-correlation within +-W samples
        (for clock jitter, or for captures with hiding on). Needs numpy.

"make sim-se-tvla" runs gen and report around the simulation.
"""
import argparse
import hashlib
import os
import random
import sys

Q = 3329
K = 3          # ML-KEM-768
ETA1 = ETA2 = 2
DU, DV = 10, 4


def bitrev7(i):
    return int(f"{i:07b}"[::-1], 2)


ZETAS = [pow(17, bitrev7(i), Q) for i in range(128)]
GAMMAS = [pow(17, 2 * bitrev7(i) + 1, Q) for i in range(128)]


def ntt(f):
    f = list(f)
    k, ln = 1, 128
    while ln >= 2:
        for start in range(0, 256, 2 * ln):
            z = ZETAS[k]
            k += 1
            for j in range(start, start + ln):
                t = z * f[j + ln] % Q
                f[j + ln] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        ln //= 2
    return f


def intt(f):
    f = list(f)
    k, ln = 127, 2
    while ln <= 128:
        for start in range(0, 256, 2 * ln):
            z = ZETAS[k]
            k -= 1
            for j in range(start, start + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % Q
                f[j + ln] = z * (f[j + ln] - t) % Q
        ln *= 2
    return [x * 3303 % Q for x in f]


def pwm(a, b):
    c = [0] * 256
    for i in range(128):
        a0, a1, b0, b1 = a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1]
        c[2 * i] = (a0 * b0 + a1 * b1 * GAMMAS[i]) % Q
        c[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return c


def padd(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def bits_of(data):
    return [(byte >> i) & 1 for byte in data for i in range(8)]


def byte_encode(f, d):
    bits = [(x >> j) & 1 for x in f for j in range(d)]
    return bytes(sum(bits[8 * i + j] << j for j in range(8)) for i in range(len(bits) // 8))


def byte_decode(data, d):
    bits = bits_of(data)
    f = [sum(bits[d * i + j] << j for j in range(d)) for i in range(256)]
    return [x % Q for x in f] if d == 12 else f


def compress(x, d):
    return ((x << (d + 1)) + Q) // (2 * Q) % (1 << d)


def decompress(y, d):
    return (y * Q + (1 << (d - 1))) >> d


def sample_ntt(seed):
    n = 840
    while True:
        buf = hashlib.shake_128(seed).digest(n)
        a, i = [], 0
        while len(a) < 256 and i + 3 <= len(buf):
            d1 = buf[i] + 256 * (buf[i + 1] % 16)
            d2 = buf[i + 1] // 16 + 16 * buf[i + 2]
            i += 3
            if d1 < Q:
                a.append(d1)
            if d2 < Q and len(a) < 256:
                a.append(d2)
        if len(a) == 256:
            return a
        n *= 2


def cbd(data, eta):
    bits = bits_of(data)
    return [(sum(bits[2 * i * eta + j] for j in range(eta)) -
             sum(bits[2 * i * eta + eta + j] for j in range(eta))) % Q for i in range(256)]


def prf(s, b, eta):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def kpke_encrypt(ek, m, r):
    t = [byte_decode(ek[384 * i: 384 * (i + 1)], 12) for i in range(K)]
    rho = ek[384 * K:]
    A = [[sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]
    n = 0
    y = []
    for _ in range(K):
        y.append(ntt(cbd(prf(r, n, ETA1), ETA1)))
        n += 1
    e1 = []
    for _ in range(K):
        e1.append(cbd(prf(r, n, ETA2), ETA2))
        n += 1
    e2 = cbd(prf(r, n, ETA2), ETA2)
    u = []
    for i in range(K):
        acc = [0] * 256
        for j in range(K):
            acc = padd(acc, pwm(A[j][i], y[j]))
        u.append(padd(intt(acc), e1[i]))
    mu = [decompress(b, 1) for b in byte_decode(m, 1)]
    acc = [0] * 256
    for j in range(K):
        acc = padd(acc, pwm(t[j], y[j]))
    v = padd(padd(intt(acc), e2), mu)
    c1 = b"".join(byte_encode([compress(x, DU) for x in u[i]], DU) for i in range(K))
    c2 = byte_encode([compress(x, DV) for x in v], DV)
    return c1 + c2


def encaps_internal(ek, m):
    g = hashlib.sha3_512(m + hashlib.sha3_256(ek).digest()).digest()
    return g[:32], kpke_encrypt(ek, m, g[32:])


def read_hex(path, n):
    with open(path) as f:
        data = bytes(int(line, 16) for line in f.read().split())
    return data[:n]


def cmd_gen(args):
    vec = args.vectors
    en_ek = read_hex(os.path.join(vec, "en_ek.hex"), 1184)
    en_m = read_hex(os.path.join(vec, "en_m.hex"), 32)
    en_c = read_hex(os.path.join(vec, "en_c.hex"), 1088)
    en_k = read_hex(os.path.join(vec, "en_k.hex"), 32)
    kk, cc = encaps_internal(en_ek, en_m)
    if kk != en_k or cc != en_c:
        print("ERROR: the Python ML-KEM model does not match the NIST Encaps vector")
        return 1
    print("[PASS] Python ML-KEM-768 Encaps matches the NIST vector")
    dk = read_hex(os.path.join(vec, "kg_dk.hex"), 2400)
    ek = dk[1152:1152 + 1184]
    rnd = random.Random(args.seed)
    m_fixed = bytes(rnd.getrandbits(8) for _ in range(32))
    classes = [0] * (args.n // 2) + [1] * (args.n - args.n // 2)
    rnd.shuffle(classes)
    with open(args.out, "w") as f:
        f.write(f"{args.n}\n")
        for k, c in enumerate(classes):
            m = m_fixed if c == 0 else bytes(rnd.getrandbits(8) for _ in range(32))
            coins = bytes(rnd.getrandbits(8) for _ in range(32))
            ct = kpke_encrypt(ek, m, coins)
            f.write(f"{c} " + " ".join(f"{b:02x}" for b in ct) + "\n")
            if (k + 1) % 50 == 0:
                print(f"  {k + 1} / {args.n} ciphertexts")
    print(f"wrote {args.out}: {args.n} ciphertexts ({classes.count(0)} fixed m, {classes.count(1)} random m)")
    return 0


TH = 4.5


def t_tail2(x, df):
    """P(|T| > x) for Student's t with df degrees of freedom (numerical integration)."""
    import math
    c = math.exp(math.lgamma((df + 1) / 2) - math.lgamma(df / 2)) / math.sqrt(df * math.pi)
    a, b, n = x, x + 60.0, 6000
    h = (b - a) / n
    f = lambda u: c * (1 + u * u / df) ** (-(df + 1) / 2)
    s = f(a) + f(b) + sum((4 if i % 2 else 2) * f(a + i * h) for i in range(1, n))
    return 2 * s * h / 3


def read_t(path):
    rows = []
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) == 3:
                rows.append((int(p[0]), int(p[1]), float(p[2])))
    return rows


def cmd_report(args):
    rows = read_t(args.tvla_t)
    if not rows:
        print("no samples in", args.tvla_t)
        return 1
    tmax = max(rows, key=lambda r: abs(r[2]))
    leaks = [r for r in rows if abs(r[2]) > TH]
    live = sum(1 for r in rows if r[2] != 0.0)      # samples that vary at all
    p1 = t_tail2(TH, max(args.traces - 2, 1))
    expect = live * p1
    print(f"samples: {len(rows)} ({live} not constant), max |t| = {abs(tmax[2]):.2f} "
          f"at sample {tmax[0]} (pc {tmax[1]})")
    print(f"with {args.traces} traces and no leak at all, about {expect:.1f} samples exceed |t| = {TH} "
          f"by chance (P = {p1:.1e} per sample, {live} tests)")
    if leaks:
        by_pc = {}
        for s, pc, t in leaks:
            n, m = by_pc.get(pc, (0, 0.0))
            by_pc[pc] = (n + 1, max(m, abs(t)))
        if set(by_pc) == {0}:                       # board traces: no instruction info
            print(f"{len(leaks)} samples above |t| = {TH}; the largest:")
            for s, _, t in sorted(leaks, key=lambda r: -abs(r[2]))[:20]:
                print(f"  sample {s:8d}  t = {t:+.2f}")
        else:
            print(f"{len(leaks)} samples above |t| = {TH}, by microcode instruction (hw/se/pqse_ucode.v):")
            for pc in sorted(by_pc):
                n, m = by_pc[pc]
                print(f"  pc {pc:3d}: {n:6d} samples, max |t| {m:.1f}")
        # a real first-order leak in a masked gadget repeats at every coefficient
        # (hundreds of samples) and |t| grows like sqrt(traces)
        clustered = max(n for n, _ in by_pc.values()) >= 5
        if len(leaks) <= 3 * expect + 3 and not clustered and abs(tmax[2]) < 6.0:
            print("RESULT: inconclusive - as many crossings as chance predicts. Confirm with a second,")
            print("        independent run (different SEED): a real leak shows up at the same sample")
            print("        with the same sign, and with more traces |t| grows. See 'confirm'.")
        else:
            print("RESULT: first-order leakage detected")
    else:
        print(f"RESULT: no first-order leakage detected (|t| <= {TH} everywhere)")
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        xs = [r[0] for r in rows]
        ts = [r[2] for r in rows]
        plt.figure(figsize=(12, 4))
        plt.plot(xs, ts, linewidth=0.4)
        plt.axhline(4.5, color="r", linewidth=0.8)
        plt.axhline(-4.5, color="r", linewidth=0.8)
        board = all(r[1] == 0 for r in rows)
        plt.xlabel("oscilloscope sample (from the trigger)" if board else
                   "clock (from the first instruction after the reseed)")
        plt.ylabel("Welch t")
        plt.title("PQSE masked Decaps, fixed-vs-random m, " +
                  ("measured traces" if board else "Hamming-distance power model"))
        plt.tight_layout()
        plt.savefig(args.png, dpi=120)
        print("plot:", args.png)
    except ImportError:
        print("(install matplotlib for the plot)")
    return 0


def cmd_confirm(args):
    """TVLA's two-set rule: a leak counts only if both independent runs exceed the
    threshold at the same sample with the same sign."""
    a = {s: (pc, t) for s, pc, t in read_t(args.t1)}
    b = {s: (pc, t) for s, pc, t in read_t(args.t2)}
    both = [(s, a[s][0], a[s][1], b[s][1]) for s in sorted(set(a) & set(b))
            if abs(a[s][1]) > TH and abs(b[s][1]) > TH and (a[s][1] > 0) == (b[s][1] > 0)]
    na = sum(1 for v in a.values() if abs(v[1]) > TH)
    nb = sum(1 for v in b.values() if abs(v[1]) > TH)
    print(f"run 1: {na} samples above {TH}; run 2: {nb}; in both with the same sign: {len(both)}")
    for s, pc, t1, t2 in both[:50]:
        print(f"  sample {s:7d}  pc {pc:3d}  t = {t1:+.2f} / {t2:+.2f}")
    if both:
        print("RESULT: first-order leakage confirmed")
        return 1
    print("RESULT: no confirmed first-order leakage")
    return 0


def read_classes(path):
    """Class (0 fixed, 1 random) of every ciphertext in a 'gen' file, in order."""
    with open(path) as f:
        n = int(f.readline())
        cls = [int(line.split()[0]) for line in f if line.strip()]
    return cls[:n]


def load_traces(path):
    import numpy as np
    if path.endswith(".npy"):
        return np.load(path, mmap_mode="r")
    return np.loadtxt(path, delimiter="," if path.endswith(".csv") else None, ndmin=2)


def cmd_board(args):
    """Welch t per sample over oscilloscope traces (fixed vs random class)."""
    try:
        import numpy as np
    except ImportError:
        print("board mode needs numpy: pip install numpy")
        return 1
    tr = load_traces(args.traces_file)
    cls = np.array(read_classes(args.tvla_in), dtype=np.int8)
    n = min(len(tr), len(cls))
    if len(tr) != len(cls):
        print(f"note: {len(tr)} traces for {len(cls)} ciphertexts - using the first {n} "
              "(the capture order must be the order of the file)")
    s = tr.shape[1]
    w = args.align
    ref = None
    if w:
        ref = np.asarray(tr[:min(n, 50)], dtype=np.float64).mean(axis=0)
        ref = ref - ref.mean()

    def aligned(x):
        if not w:
            return x
        out = np.empty_like(x)
        core = slice(w, s - w)
        for k in range(len(x)):
            row = x[k] - x[k].mean()
            best = max(range(-w, w + 1), key=lambda d: float(np.dot(np.roll(row, d)[core], ref[core])))
            out[k] = np.roll(x[k], best)
        return out

    s0 = np.zeros(s); q0 = np.zeros(s); s1 = np.zeros(s); q1 = np.zeros(s)
    n0 = n1 = 0
    for a in range(0, n, 256):
        b = min(n, a + 256)
        x = aligned(np.asarray(tr[a:b], dtype=np.float64))
        c = cls[a:b] == 1
        s1 += x[c].sum(axis=0); q1 += (x[c] ** 2).sum(axis=0); n1 += int(c.sum())
        s0 += x[~c].sum(axis=0); q0 += (x[~c] ** 2).sum(axis=0); n0 += int((~c).sum())
    if n0 < 2 or n1 < 2:
        print("need at least two traces of each class")
        return 1
    m0, m1 = s0 / n0, s1 / n1
    v0 = np.maximum((q0 - n0 * m0 * m0) / (n0 - 1), 0.0)
    v1 = np.maximum((q1 - n1 * m1 * m1) / (n1 - 1), 0.0)
    den = np.sqrt(v0 / n0 + v1 / n1)
    t = np.where(den > 1e-12, (m0 - m1) / np.where(den > 1e-12, den, 1.0), 0.0)
    with open(args.out, "w") as f:
        for i in range(s):
            f.write(f"{i} 0 {t[i]:.3f}\n")
    print(f"board TVLA: {n0} + {n1} traces, {s} samples per trace -> {args.out}")
    args.tvla_t = args.out
    args.traces = n
    return cmd_report(args)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    bd = sub.add_parser("board")
    bd.add_argument("traces_file")
    bd.add_argument("tvla_in")
    bd.add_argument("--out", default="tvla_board_t.txt")
    bd.add_argument("--png", default="tvla_board_t.png")
    bd.add_argument("--align", type=int, default=0)
    g = sub.add_parser("gen")
    g.add_argument("n", type=int)
    g.add_argument("out")
    g.add_argument("--vectors", default="hw/sim/vectors")
    g.add_argument("--seed", type=int, default=1)
    r = sub.add_parser("report")
    r.add_argument("tvla_t")
    r.add_argument("--png", default="tvla_t.png")
    r.add_argument("--traces", type=int, default=200)
    c = sub.add_parser("confirm")
    c.add_argument("t1")
    c.add_argument("t2")
    args = ap.parse_args()
    if args.cmd == "gen":
        return cmd_gen(args)
    if args.cmd == "confirm":
        return cmd_confirm(args)
    if args.cmd == "board":
        return cmd_board(args)
    return cmd_report(args)


if __name__ == "__main__":
    sys.exit(main())
