#!/usr/bin/env python3
"""Bit-exact model of the PQSE masked gadgets (hw/se) and checks of their math.

    python3 scripts/pqse_model.py          (run by "make sim-se" before the RTL test)
    python3 scripts/pqse_model.py --quick  (fewer samples)

Checks
  1. the scaling constants M_d of pqse_mcomp.v
  2. masked Compress_d (d = 1, 4, 10): per-share scaling + offset + mod 2^K
     addition gives exactly Compress_d(x0 + x1 mod q), also with the share-1
     negation used for w = v' - acc0 - acc1. With numpy installed: every
     (x0, x1) pair for d = 1 and 4, and a dense random sample for d = 10.
  3. the bit-serial masked adder with DOM AND gates and registered carry
     shares (Boolean level, random masks) against plain addition
  4. the B2A gadget for weights 1, q-1, 1665 and every b0, b1
  5. a quick statistical first-order probing test of the adder over its full
     width (value-based; the exact robust-probing proof with glitches and
     transitions, on reduced widths, is scripts/pqse_probe_verify.py)
  6. the PUF fuzzy extractor (pqse_puf.v): RM(1,5) is linear with minimum
     distance 16, the masked maximum-likelihood decoder corrects every error
     pattern of weight <= 7 and returns (k ^ R, R), and the key failure rate
     of the 30-block extractor at 3 / 5 / 10 / 15 % response bit errors
  7. the reconstruction with the key check value and majority retries (one
     read per bit, then the majority of 3, then of 5): key failure rate at 5
     to 20 % bit errors per read, against one read only
  8. the inside-out Fisher-Yates shuffle of pqse_perm.v (T[i] := T[j],
     T[j] := i, j = floor(r (i + 1) / 2^24)) is always a permutation and
     places every element uniformly
Exit status 0 if everything holds.
"""
import random
import sys

Q = 3329
L = 14            # fractional margin bits: K = d + L
S = 16            # fixed-point bits of the scaling multiply
M_RTL = {1: 645084, 4: 5160670, 10: 330282856}   # constants in pqse_mcomp.v

failures = 0


def check(cond, what):
    global failures
    if cond:
        print(f"[PASS] {what}")
    else:
        print(f"[FAIL] {what}")
        failures += 1


def compress(x, d):
    """FIPS 203 Compress_d: round(2^d x / q) mod 2^d (round half up)."""
    return ((x << (d + 1)) + Q) // (2 * Q) % (1 << d)


def scale(x, d):
    K = d + L
    return ((x * M_RTL[d] + (1 << (S - 1))) >> S) % (1 << K)


def masked_compress(x0, x1, d, neg1=False):
    """What pqse_mcomp.v computes (arithmetically), shares x0 + x1 mod q."""
    K = d + L
    if neg1:
        x1 = (Q - x1) % Q
    y0 = (scale(x0, d) + (1 << (L - 1))) % (1 << K)
    y1 = scale(x1, d)
    z = (y0 + y1) % (1 << K)
    return z >> L


# ---- 1 constants -------------------------------------------------------------------------
for d in (1, 4, 10):
    K = d + L
    exact = round((1 << (K + S)) / Q)
    check(M_RTL[d] == exact, f"M_{d} = round(2^{K + S} / q) = {exact}")

# ---- 2 masked compress ----------------------------------------------------------------------
quick = "--quick" in sys.argv
try:
    import numpy as np
except ImportError:
    np = None

if np is not None and not quick:
    for d in (1, 4):
        K = d + L
        x0 = np.arange(Q, dtype=np.int64)
        bad = 0
        for x1v in range(Q):
            for neg in (False, True):
                x1 = (Q - x1v) % Q if neg else x1v
                y0 = (((x0 * M_RTL[d] + (1 << (S - 1))) >> S) + (1 << (L - 1))) % (1 << K)
                y1 = ((x1 * M_RTL[d] + (1 << (S - 1))) >> S) % (1 << K)
                got = ((y0 + y1) % (1 << K)) >> L
                x = (x0 + (x1v if not neg else -x1v)) % Q
                want = ((x << (d + 1)) + Q) // (2 * Q) % (1 << d)
                bad += int(np.count_nonzero(got != want))
        check(bad == 0, f"masked Compress_{d}: all {Q * Q} share pairs, with and without negation")
    d = 10
    rng = np.random.default_rng(1)
    x0 = rng.integers(0, Q, 4_000_000)
    x1 = rng.integers(0, Q, 4_000_000)
    K = d + L
    y0 = (((x0 * M_RTL[d] + (1 << (S - 1))) >> S) + (1 << (L - 1))) % (1 << K)
    y1 = ((x1 * M_RTL[d] + (1 << (S - 1))) >> S) % (1 << K)
    got = ((y0 + y1) % (1 << K)) >> L
    x = (x0 + x1) % Q
    want = ((x << (d + 1)) + Q) // (2 * Q) % (1 << d)
    bad = int(np.count_nonzero(got != want))
    # every x, every x0 (x1 = x - x0): exhaustive over x with 64 random x0 each
    xs = np.repeat(np.arange(Q, dtype=np.int64), 64)
    x0 = rng.integers(0, Q, xs.size)
    x1 = (xs - x0) % Q
    y0 = (((x0 * M_RTL[d] + (1 << (S - 1))) >> S) + (1 << (L - 1))) % (1 << K)
    y1 = ((x1 * M_RTL[d] + (1 << (S - 1))) >> S) % (1 << K)
    got = ((y0 + y1) % (1 << K)) >> L
    want = ((xs << (d + 1)) + Q) // (2 * Q) % (1 << d)
    bad += int(np.count_nonzero(got != want))
    check(bad == 0, "masked Compress_10: 4M random pairs + every x with 64 splits")
else:
    rnd = random.Random(1)
    n = 20000 if quick else 200000
    for d in (1, 4, 10):
        bad = 0
        for _ in range(n):
            x0, x1 = rnd.randrange(Q), rnd.randrange(Q)
            neg = rnd.random() < 0.5
            x = (x0 - x1) % Q if neg else (x0 + x1) % Q
            bad += masked_compress(x0, x1, d, neg) != compress(x, d)
        check(bad == 0, f"masked Compress_{d}: {n} random share pairs (install numpy for the exhaustive test)")


# ---- 3 bit-serial masked adder, Boolean level ------------------------------------------------------
def masked_add_bits(y0, y1, K, rnd, trace=None):
    """pqse_mcomp.v S_RF, then per bit S_AD (AND clock) and S_AC (compress clock):
    returns the Boolean shares of every sum bit."""
    R, Rp = rnd.getrandbits(K), rnd.getrandbits(K)
    A0, A1 = y0 ^ R, R           # a = y0 shared
    B0, B1 = Rp, y1 ^ Rp         # b = y1 shared
    C0 = C1 = 0                  # carry share registers (0 into bit 0)
    out = []
    for i in range(K):
        a0, a1, b0, b1 = (A0 >> i) & 1, (A1 >> i) & 1, (B0 >> i) & 1, (B1 >> i) & 1
        P0, P1, Q0, Q1 = a0 ^ b0, a1 ^ b1, a0 ^ C0, a1 ^ C1
        s0, s1 = P0 ^ C0, P1 ^ C1
        out.append((s0, s1))
        r = rnd.getrandbits(1)
        p00, p01, p10, p11 = P0 & Q0, (P0 & Q1) ^ r, (P1 & Q0) ^ r, P1 & Q1   # AND clock
        if trace is not None:
            trace.append((a0, a1, b0, b1, C0, C1, P0, P1, Q0, Q1, s0, s1, p00, p01, p10, p11))
        C0, C1 = a0 ^ p00 ^ p01, a1 ^ p11 ^ p10                               # compress clock
    return out


rnd = random.Random(2)
bad = 0
for _ in range(20000 if quick else 100000):
    K = rnd.choice((15, 18, 24))
    y0, y1 = rnd.getrandbits(K), rnd.getrandbits(K)
    bits = masked_add_bits(y0, y1, K, rnd)
    z = sum((s0 ^ s1) << i for i, (s0, s1) in enumerate(bits))
    bad += z != (y0 + y1) % (1 << K)
check(bad == 0, "masked bit-serial adder (DOM AND carries) = plain addition mod 2^K")

# ---- 4 B2A gadget ---------------------------------------------------------------------------------
bad = 0
for v in (1, Q - 1, 1665):
    for b0 in (0, 1):
        for b1 in (0, 1):
            for _ in range(2000):
                R = rnd.randrange(Q)
                T = (v * b0 - R) % Q
                A0 = (Q - T) % Q if b1 else T
                A1 = (v - R) % Q if b1 else R
                bad += (A0 + A1) % Q != (v * (b0 ^ b1)) % Q
check(bad == 0, "B2A: A0 + A1 = v (b0 XOR b1) mod q for v = 1, q-1, 1665")


# ---- 5 first-order probing test of the masked adder ---------------------------------------------
def probe_means(y0, y1, K, n, seed):
    """mean of every intermediate bit over random masks for a fixed secret y0 + y1."""
    r = random.Random(seed)
    sums = None
    for _ in range(n):
        tr = []
        # fresh arithmetic sharing of the secret too: y0 random, y1 = secret - y0
        secret = (y0 + y1) % (1 << K)
        a = r.getrandbits(K)
        masked_add_bits(a, (secret - a) % (1 << K), K, r, tr)
        flat = [b for step in tr for b in step]
        sums = flat if sums is None else [s + b for s, b in zip(sums, flat)]
    return [s / n for s in sums]


n = 3000 if quick else 20000
K = 15
mA = probe_means(0x0000, 0x2000, K, n, 10)     # two secrets with different top bits
mB = probe_means(0x0000, 0x6000, K, n, 11)
worst = max(abs(a - b) for a, b in zip(mA, mB))
# a probe that sees an unmasked bit would differ by ~0.5; statistical noise is ~2/sqrt(n)
check(worst < 6 / n ** 0.5, f"first-order probes of the masked adder: max mean difference {worst:.4f}")

# ---- 6 PUF fuzzy extractor: RM(1,5) code offset with masked decoding (pqse_puf.v) ---------------
def rm_cw(m):
    """RM(1,5) codeword of the 6-bit message m (m[0]: all-ones row, m[5:1]: x's bits)."""
    v = 0
    for x in range(32):
        bit = (m & 1) ^ (bin((m >> 1) & x).count("1") & 1)
        v |= bit << x
    return v


CW = [rm_cw(m) for m in range(64)]


def rm_decode(y):
    """pqse_puf.v U_DEC: scan u = 0..31, candidate (u,0) at distance dist or (u,1) at
    32 - dist; strictly smaller distances replace the best (first minimum wins)."""
    best, bm = 63, 0
    for u in range(32):
        dist = bin(y ^ CW[u << 1]).count("1")
        dinv = 32 - dist
        use1 = dinv < dist
        cand = dinv if use1 else dist
        if cand < best:
            best, bm = cand, (u << 1) | int(use1)
    return bm


def flip_random(v, w, rnd):
    for b in rnd.sample(range(32), w):
        v ^= 1 << b
    return v


# the code: linear, minimum distance 16
lin = all(CW[a] ^ CW[b] == CW[a ^ b] for a in range(64) for b in range(64))
dmin = min(bin(CW[m]).count("1") for m in range(1, 64))
check(lin and dmin == 16, f"RM(1,5): linear, minimum distance {dmin}")

# every error of weight <= 7 is corrected; masked decoding y = r ^ w ^ C(R) gives k ^ R
bad = 0
for _ in range(10000 if quick else 50000):
    k, R = rnd.randrange(64), rnd.randrange(64)
    r = rnd.getrandbits(32)                   # enrolled response
    w = r ^ CW[k]                             # helper data
    r2 = flip_random(r, rnd.randrange(8), rnd)  # re-read with 0..7 bit errors
    y = r2 ^ w ^ CW[R]                        # what the decoder sees (never C(k) alone)
    d = rm_decode(y)
    bad += (d ^ R) != k
check(bad == 0, "RM(1,5) masked decoding: every error pattern of weight <= 7 gives (k ^ R, R)")

# key failure rate of the 30-block extractor against the response bit-error rate
print("       PUF key failure rate (30 blocks, 180-bit key) vs response bit-error rate:")
for ber in (0.03, 0.05, 0.10, 0.15):
    fails, trials = 0, (500 if quick else 3000)
    for _ in range(trials):
        ok = True
        for _b in range(30):
            k = rnd.randrange(64)
            e = sum(1 << i for i in range(32) if rnd.random() < ber)
            if rm_decode(CW[k] ^ e) != k:
                ok = False
                break
        fails += not ok
    print(f"         BER {ber:4.0%}: {fails}/{trials} keys wrong")
    if ber == 0.03:
        check(fails <= trials // 1000, "PUF key failure rate < 1e-3 at 3% bit errors")

# ---- 7 PUF reconstruction with the check value and majority retries (pqse_ucode.v 48) ------------
def recon_ok(key, ber, reads, rnd):
    """One reconstruction of a 30-block key: every response bit read `reads` times
    (majority), then ML decoding; True if the decoded key is right (the check value
    would match)."""
    for blk in range(30):
        e = 0
        for i in range(32):
            wrong = sum(rnd.random() < ber for _ in range(reads))
            if 2 * wrong > reads:
                e |= 1 << i
        if rm_decode(CW[key[blk]] ^ e) != key[blk]:
            return False
    return True


print("       PUF key failure rate per UNWRAP, bit errors per read (independent reads):")
print("         BER    1 read     retry 1 -> 3 -> 5 reads (as the microcode does)")
retry_ok = True
for ber in (0.05, 0.10, 0.15, 0.20):
    trials = 150 if quick else 600
    f1 = fr = 0
    for _ in range(trials):
        key = [rnd.randrange(64) for _ in range(30)]
        a1 = recon_ok(key, ber, 1, rnd)
        f1 += not a1
        if not (a1 or recon_ok(key, ber, 3, rnd) or recon_ok(key, ber, 5, rnd)):
            fr += 1
    print(f"         {ber:4.0%}   {f1:4d}/{trials}   {fr:4d}/{trials}")
    if ber == 0.10:
        retry_ok = fr <= max(1, trials // 300) and f1 > fr
check(retry_ok, "PUF retry with the majority of 3 / 5 reads: key failures at 10% bit errors "
                "far below one read only")


# ---- 8 inside-out Fisher-Yates (pqse_perm.v): T[i] := T[j], T[j] := i, j = floor(r (i + 1) / 2^24)
def fisher_yates(n, r):
    t = [0] * n
    for i in range(n):
        j = (r.getrandbits(24) * (i + 1)) >> 24      # 0 <= j <= i
        t[i] = t[j]                                   # (phase 0; for j = i: overwritten next)
        t[j] = i                                      # (phase 1)
    return t


trials = 4000 if quick else 20000
pos = [[0] * 128 for _ in range(4)]       # where elements 0, 1, 63, 127 land
ok = True
for _ in range(trials):
    t = fisher_yates(128, rnd)
    ok &= sorted(t) == list(range(128))
    for k, v in enumerate((0, 1, 63, 127)):
        pos[k][t.index(v)] += 1
exp = trials / 128
chi = max(sum((c - exp) ** 2 / exp for c in row) for row in pos)
# chi-square with 127 degrees of freedom: mean 127, 99.99th percentile ~ 200
check(ok and chi < 210, f"Fisher-Yates: always a permutation, positions uniform "
                        f"(worst chi-square {chi:.0f}, 127 degrees of freedom)")

print("----------------------------------------------------------------")
if failures == 0:
    print("MODEL CHECKS PASSED")
else:
    print(f"MODEL CHECKS FAILED: {failures}")
sys.exit(1 if failures else 0)
