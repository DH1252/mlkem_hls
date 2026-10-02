#!/usr/bin/env python3
"""
gen_keccak.py - generate keccak_f1600() for src/fips202.c.

The permutation is written out as straight-line C: the 25 lanes live in the
local variables a0..a24, and theta, rho, pi, chi and iota of one round are
spelled out lane by lane. For an HLS tool that is much better than the usual
loops over a 25-entry array: there is no array to put in a memory, every lane
becomes a 64-bit register and a round becomes a block of XOR/AND/NOT logic.

    python3 scripts/gen_keccak.py                 print the function
    python3 scripts/gen_keccak.py --check FILE    check FILE contains exactly it

Lane i = x + 5*y (FIPS 202, section 3.1.2).
"""
import sys

# Rotation offsets r[x + 5y] (FIPS 202, Table 2)
RHO = [0, 1, 62, 28, 27,
       36, 44, 6, 55, 20,
       3, 10, 43, 25, 39,
       41, 45, 15, 21, 8,
       18, 2, 61, 56, 14]


def generate():
    L = []
    w = L.append
    lanes = ", ".join("a%d" % i for i in range(25))
    temps = ", ".join("b%d" % i for i in range(25))
    w("MLKEM_LEAF void keccak_f1600(uint64_t st[25])")
    w("{")
    w("   uint64_t %s;" % lanes)
    w("   uint64_t %s;" % temps)
    w("   uint64_t c0, c1, c2, c3, c4, d0, d1, d2, d3, d4;")
    w("   int round;")
    w("")
    for i in range(25):
        w("   a%d = st[%d];" % (i, i))
    w("")
    w("   for(round = 0; round < 24; round++)")
    w("   {")
    w("      /* theta */")
    for x in range(5):
        w("      c%d = %s;" % (x, " ^ ".join("a%d" % (x + 5 * y) for y in range(5))))
    for x in range(5):
        w("      d%d = c%d ^ ROL64(c%d, 1);" % (x, (x + 4) % 5, (x + 1) % 5))
    for i in range(25):
        w("      a%d ^= d%d;" % (i, i % 5))
    w("      /* rho and pi: lane (x,y) moves to (y, 2x+3y) and is rotated */")
    for i in range(25):
        x, y = i % 5, i // 5
        j = y + 5 * ((2 * x + 3 * y) % 5)
        if RHO[i] == 0:
            w("      b%d = a%d;" % (j, i))
        else:
            w("      b%d = ROL64(a%d, %d);" % (j, i, RHO[i]))
    w("      /* chi */")
    for i in range(25):
        x, y = i % 5, i // 5
        w("      a%d = b%d ^ (~b%d & b%d);" % (i, i, (x + 1) % 5 + 5 * y, (x + 2) % 5 + 5 * y))
    w("      /* iota */")
    w("      a0 ^= keccak_rc[round];")
    w("   }")
    w("")
    for i in range(25):
        w("   st[%d] = a%d;" % (i, i))
    w("}")
    return "\n".join(L) + "\n"


def main():
    code = generate()
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        text = open(sys.argv[2]).read()
        if code in text:
            print("%s: keccak_f1600 matches the generator" % sys.argv[2])
            return 0
        print("%s: keccak_f1600 differs from the generator output" % sys.argv[2])
        return 1
    sys.stdout.write(code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
