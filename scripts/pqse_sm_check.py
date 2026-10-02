#!/usr/bin/env python3
"""Check the PQSE secure-messaging output (SEAL) with an independent KMAC.

    python3 scripts/pqse_sm_check.py build/sesim/sm_vec.txt
    python3 scripts/pqse_sm_check.py --selftest

Each line of sm_vec.txt (written by hw/sim/tb_pqse.sv) is
    dir K H M C T                       (hex; dir 1 = initiator -> responder)
H is the 32-byte header: the 64-bit message counter and the 64-bit message
length L (both little-endian), then 16 zero bytes. M is the 128-byte buffer
the host wrote (bytes from L on are ignored). Each line must satisfy
    KS = KMACXOF256(K, H, 1024 bits, S = "E" || dir)
    C  = (M[0..L-1] xor KS[0..L-1]) || zero bytes up to 128
    T  = KMAC256(K, H || C, 256 bits, S = "T" || dir)
(NIST SP 800-185. K is the ML-KEM shared secret that the device keeps as its
session key; the testbench reads it in lifecycle TEST, where Encaps / Decaps
export it.)

Keccak-f[1600], cSHAKE and KMAC are implemented here from the standards, in
plain Python, so the check does not depend on the hardware's own reading of
SP 800-185. Before the vectors are checked, the implementation tests itself:
the sponge against hashlib's SHA3-256 / SHAKE256, and KMAC against the NIST
SP 800-185 example values (KMAC_samples.pdf).
"""
import hashlib
import sys

M64 = (1 << 64) - 1
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
# rotation offsets r[x][y]
ROT = [[0, 36, 3, 41, 18],
       [1, 44, 10, 45, 2],
       [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56],
       [27, 20, 39, 8, 14]]


def rol(v, n):
    return ((v << n) | (v >> (64 - n))) & M64 if n else v


def keccak_f(a):
    """Keccak-f[1600] on 25 lanes, lane (x, y) at index x + 5 y."""
    for rnd in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(a[x + 5 * y], ROT[x][y])
        a = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)])
             for i in range(25)]
        a[0] ^= RC[rnd]
    return a


def sponge(rate, data, pad, outlen):
    """Keccak sponge, rate in bytes, pad = domain byte (0x06 SHA3, 0x1F SHAKE, 0x04 cSHAKE)."""
    a = [0] * 25
    p = bytearray(data) + bytes([pad])
    while len(p) % rate:
        p.append(0)
    p[-1] |= 0x80
    for off in range(0, len(p), rate):
        for i in range(rate // 8):
            a[i] ^= int.from_bytes(p[off + 8 * i: off + 8 * i + 8], "little")
        a = keccak_f(a)
    out = bytearray()
    while True:
        for i in range(rate // 8):
            out += a[i].to_bytes(8, "little")
        if len(out) >= outlen:
            return bytes(out[:outlen])
        a = keccak_f(a)


# ---- SP 800-185 --------------------------------------------------------------------------
def left_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return bytes([n]) + x.to_bytes(n, "big")


def right_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(n, "big") + bytes([n])


def encode_string(s):
    return left_encode(8 * len(s)) + s


def bytepad(x, w):
    z = left_encode(w) + x
    return z + bytes((w - len(z) % w) % w)


def cshake(rate, x, outlen, n, s):
    if not n and not s:
        return sponge(rate, x, 0x1F, outlen)
    return sponge(rate, bytepad(encode_string(n) + encode_string(s), rate) + x, 0x04, outlen)


def kmac(rate, k, x, lbits, s, xof=False):
    newx = bytepad(encode_string(k), rate) + x + right_encode(0 if xof else lbits)
    return cshake(rate, newx, lbits // 8, b"KMAC", s)


def kmac256(k, x, lbits, s):
    return kmac(136, k, x, lbits, s)


def kmacxof256(k, x, lbits, s):
    return kmac(136, k, x, lbits, s, xof=True)


# ---- self test ---------------------------------------------------------------------------
def selftest():
    ok = True
    for msg in (b"", b"abc", bytes(range(200)), bytes(135), bytes(136), bytes(300)):
        if sponge(136, msg, 0x06, 32) != hashlib.sha3_256(msg).digest():
            print(f"[FAIL] self test: SHA3-256 of {len(msg)} bytes")
            ok = False
        if sponge(136, msg, 0x1F, 200) != hashlib.shake_256(msg).digest(200):
            print(f"[FAIL] self test: SHAKE256 of {len(msg)} bytes")
            ok = False
    key = bytes(range(0x40, 0x60))
    data = bytes([0, 1, 2, 3])
    tag = b"My Tagged Application"
    kat = [
        ("KMAC128 sample 1", kmac(168, key, data, 256, b""),
         "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"),
        ("KMAC128 sample 2", kmac(168, key, data, 256, tag),
         "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"),
        ("KMAC256 sample 4", kmac256(key, data, 512, tag),
         "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7"
         "F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"),
        ("KMACXOF256 sample 4", kmacxof256(key, data, 512, tag),
         "1755133F1534752AAD0748F2C706FB5C784512CAB835CD15676B16C0C6647FA9"
         "6FAA7AF634A0BF8FF6DF39374FA00FAD9A39E322A7C92065A64EB1FB0801EB2B"),
    ]
    for name, got, want in kat:
        if got.hex().upper() != want:
            print(f"[FAIL] self test: {name}: {got.hex().upper()}")
            ok = False
    print("[PASS] KMAC self test (hashlib SHA3 / SHAKE, NIST SP 800-185 samples)" if ok
          else "KMAC SELF TEST FAILED")
    return ok


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    if not selftest():
        return 1
    if sys.argv[1] == "--selftest":
        return 0
    bad = n = 0
    with open(sys.argv[1]) as f:
        for line in f:
            p = line.split()
            if len(p) != 6:
                continue
            d = int(p[0])
            k, hdr, m, c, t = (bytes.fromhex(x) for x in p[1:])
            ctr = int.from_bytes(hdr[:8], "little")
            ln = int.from_bytes(hdr[8:16], "little")
            hdr_ok = len(hdr) == 32 and 1 <= ln <= 128 and hdr[16:] == bytes(16)
            n += 1
            if not hdr_ok:
                print(f"[FAIL] SEAL direction {d}, counter {ctr}: header WRONG (length {ln})")
                bad += 1
                continue
            dch = str(d).encode()
            ks = kmacxof256(k, hdr, 1024, b"E" + dch)
            c_ref = bytes(m[i] ^ ks[i] for i in range(ln)) + bytes(128 - ln)
            t_ref = kmac256(k, hdr + c_ref, 256, b"T" + dch)
            ok = c == c_ref and t == t_ref
            bad += not ok
            print(f"[{'PASS' if ok else 'FAIL'}] SEAL direction {d}, counter {ctr}, length {ln}: "
                  f"ciphertext {'ok' if c == c_ref else 'WRONG'}, tag {'ok' if t == t_ref else 'WRONG'}")
    if n == 0:
        print("no sealed messages found")
        return 1
    print("SM CHECK PASSED" if bad == 0 else f"SM CHECK FAILED: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
