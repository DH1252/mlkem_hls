#!/usr/bin/env python3
"""PUF and TRNG statistics from the PQSE raw dumps (commands PUFRAW / TRNGRAW,
lifecycle TEST only).

    python3 scripts/pqse_puf_stats.py --puf puf_raw.txt [--puf other_board.txt ...]
                                      [--trng trng_raw.txt] [--out DIR]

puf_raw.txt   one line per PUFRAW command: 240 hex digits = 960 response bits
              (the helper window of ENROLL is 128 bytes: 120 bytes of helper
              data + the 8-byte key check value; PUFRAW dumps only the 120)
              (written by hw/sim/tb_pqse.sv, or by quartus/jtag/pqse_test.tcl
              "dump" on the board). Several dumps of one device give the
              reliability (bit-error rate between reads); dumps of several
              devices (one file each) give the uniqueness.
trng_raw.txt  one line per TRNGRAW command: 2176 hex digits = 8704 bits

Reports
  PUF   uniformity (fraction of ones), bit-error rate between the reads of one
        device (reliability: the fuzzy extractor needs it well below 22%), the
        inter-device distance (uniqueness, ideal 50%), the key failure rate of
        the RM(1,5) extractor expected for the measured bit-error rate with 1,
        3 and 5 reads per bit and with the microcode's check-value retries,
        and the key entropy left after the helper data: 30 * (32 h - 26) bits,
        h = the min-entropy per response bit estimated from the bias (the
        64-bit key check value, a SHA3 hash of the key, lets an attacker test
        key guesses offline: harmless while the key keeps >= 128 bits).
        Each response bit position is counted once (re-reads of one device are
        not new samples). Reported: the point estimate and the 99% lower bound;
        128 bits need h >= 0.946, and one device's 960 bits are too few to show
        that at 99% confidence even for a perfect PUF (about 4,500 bits are:
        give the dumps of several devices, they are pooled).
        The bias estimate assumes independent response bits, which the RTL
        gives by using one SRAM-type cell per bit (pqse_puf.v). Bias is
        a necessary check, not a sufficient one: spatial / inter-device
        correlation also count (the uniqueness line shows the latter).
  TRNG  bias, longest run, the SP 800-90B most-common-value min-entropy
        estimate, and binary files for the NIST tools:
          trng_raw_bits.bin  one sample (0 / 1) per byte:
                             ea_non_iid -v trng_raw_bits.bin 1
          trng_raw.bin       the packed bytes
        (Collect at least 1,000,000 samples - about 115 TRNGRAW commands - for a
        meaningful 90B assessment; the simulation dump is only a format check.)
"""
import argparse
import math
import os
import sys
from math import comb


def read_dumps(path):
    out = []
    with open(path) as f:
        for line in f:
            s = line.strip()
            if s:
                out.append(bytes.fromhex(s))
    return out


def bits(b):
    return [(x >> i) & 1 for x in b for i in range(8)]


def hd(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def mcv_entropy(p_ones, n):
    p = max(p_ones, 1 - p_ones)
    pu = min(1.0, p + 2.576 * math.sqrt(p * (1 - p) / max(n - 1, 1)))
    return -math.log2(pu)


PUF_NB = 30                                   # blocks of 32 response bits (pqse_defs.vh)
H_NEED = (128 / PUF_NB + 26) / 32             # min-entropy per bit for a 128-bit key (0.946)


def key_bits(h):
    return PUF_NB * (32 * h - 26)


def h_point(p_ones):
    return -math.log2(max(p_ones, 1 - p_ones))


def bits_needed():
    """Sample size at which a perfect PUF (50% ones) shows h >= H_NEED at 99%."""
    return math.ceil((2.576 * 0.5 / (2 ** -H_NEED - 0.5)) ** 2)


def reference(dumps):
    """Per-position majority of a device's dumps (ties: the first dump)."""
    n = len(dumps)
    bb = [bits(d) for d in dumps]
    out = []
    for i in range(len(bb[0])):
        s = sum(b[i] for b in bb)
        out.append(1 if 2 * s > n else 0 if 2 * s < n else bb[0][i])
    return out


def entropy_report(ref, label):
    n = len(ref)
    ones = sum(ref) / n
    hp, hb = h_point(ones), mcv_entropy(ones, n)
    print(f"  min-entropy{label} {hp:.3f} bit per response bit (point estimate from the bias, "
          f"{n} bits) -> about {max(key_bits(hp), 0):.0f} key bits after the helper data")
    print(f"                   99% lower bound {hb:.3f} -> {max(key_bits(hb), 0):.0f} key bits")
    if key_bits(hp) < 128:
        print("  WARNING: the point estimate is below 128 key bits: raise PUF_NB (more blocks) "
              "or improve the PUF")
    elif key_bits(hb) < 128:
        nn = bits_needed()
        print(f"  note: {n} bits are too few to show 128 key bits at 99% confidence (needs h >= "
              f"{H_NEED:.3f}; about {nn} bits, i.e. {math.ceil(nn / 960)} devices, even for a "
              f"perfect PUF)")
    else:
        print("  128 key bits shown at 99% confidence (independent bits assumed: one cell "
              "per bit)")


def block_fail(ber, n=32, t=7):
    return sum(comb(n, k) * ber ** k * (1 - ber) ** (n - k) for k in range(t + 1, n + 1))


def puf_report(files):
    devs = [read_dumps(p) for p in files]
    for path, dumps in zip(files, devs):
        nb = 8 * len(dumps[0])
        print(f"PUF {path}: {len(dumps)} dumps of {nb} bits")
        ones = sum(sum(bits(d)) for d in dumps) / (nb * len(dumps))
        print(f"  uniformity       {ones:6.1%} ones (ideal 50%)")
        if len(dumps) >= 2:
            bers = [hd(dumps[0], d) / nb for d in dumps[1:]]
            ber = sum(bers) / len(bers)
            print(f"  reliability      {ber:6.2%} bit errors between reads "
                  f"(min {min(bers):.2%}, max {max(bers):.2%})")
            # two noisy reads differ with 2p(1-p): p = error rate of one read against the
            # (5-read majority, nearly noise-free) enrolled reference
            p = (1 - math.sqrt(max(1 - 2 * ber, 0.0))) / 2
            print(f"  per-read error   {p:6.2%} against the enrolled reference (from 2p(1-p) = BER)")
            pks = {}
            for n in (1, 3, 5):
                en = sum(comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(n // 2 + 1, n + 1))
                pks[n] = 1 - (1 - block_fail(en)) ** 30
                print(f"  RM(1,5) extractor, {n} read(s) per bit: bit errors {en:.2%}, "
                      f"key failure {pks[n]:.2e}")
            print(f"  with the check value and retries (1, then 3, then 5 reads): key failure "
                  f"{pks[1] * pks[3] * pks[5]:.2e} per unwrap (result 12 PUF)")
            print("                   (bounded-distance estimate: the ML decoder corrects some patterns")
            print("                    beyond 7 errors, so the real rates are a little lower)")
        else:
            print("  (one dump only: run PUFRAW at least twice for the bit-error rate)")
        entropy_report(reference(dumps), "     ")
    if len(devs) >= 2:
        pooled = [b for dumps in devs for b in reference(dumps)]
        print(f"PUF all {len(devs)} devices pooled:")
        entropy_report(pooled, "     ")
        nb = 8 * len(devs[0][0])
        ds = [hd(devs[i][0], devs[j][0]) / nb for i in range(len(devs)) for j in range(i + 1, len(devs))]
        print(f"PUF uniqueness: {sum(ds) / len(ds):.1%} mean inter-device distance over {len(ds)} pairs (ideal 50%)")


def trng_report(path, out_dir):
    dumps = read_dumps(path)
    data = b"".join(dumps)
    bb = bits(data)
    n = len(bb)
    ones = sum(bb) / n
    run = best = 1
    for i in range(1, n):
        run = run + 1 if bb[i] == bb[i - 1] else 1
        best = max(best, run)
    print(f"TRNG {path}: {n} bits from {len(dumps)} dumps")
    print(f"  bias             {ones:6.2%} ones")
    print(f"  longest run      {best} (the health test cuts off at 41)")
    print(f"  MCV min-entropy  {mcv_entropy(ones, n):.3f} bit/sample (SP 800-90B 6.3.1, upper bound)")
    with open(os.path.join(out_dir, "trng_raw_bits.bin"), "wb") as f:
        f.write(bytes(bb))
    with open(os.path.join(out_dir, "trng_raw.bin"), "wb") as f:
        f.write(data)
    print(f"  wrote {out_dir}/trng_raw_bits.bin (for: ea_non_iid -v trng_raw_bits.bin 1) and trng_raw.bin")
    if n < 1_000_000:
        print("  note: 90B needs >= 1,000,000 samples; this is a format / sanity check only")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--puf", action="append", default=[])
    ap.add_argument("--trng")
    ap.add_argument("--out", default=".")
    a = ap.parse_args()
    if not a.puf and not a.trng:
        ap.print_help()
        return 2
    if a.puf:
        puf_report(a.puf)
    if a.trng:
        trng_report(a.trng, a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
