#!/usr/bin/env python3
"""Convert NIST ACVP ML-KEM test vectors (JSON) to simple text files.

The official vectors live in github.com/usnistgov/ACVP-Server under
gen-val/json-files/ML-KEM-keyGen-FIPS203/ and ML-KEM-encapDecap-FIPS203/.
Each "internalProjection.json" holds the inputs together with the expected
results. This script writes one file per parameter set:

    vectors/ML-KEM-512.txt, vectors/ML-KEM-768.txt, vectors/ML-KEM-1024.txt

with one test per line (all values in hex):

    keygen  <tcId> <d> <z> <ek> <dk>
    encaps  <tcId> <ek> <m> <c> <k>
    decaps  <tcId> <dk> <c> <k> <valid|rejected>
    ekcheck <tcId> <ek> <1|0>
    dkcheck <tcId> <dk> <1|0>

Usage:
    python3 scripts/acvp_to_txt.py <path to ACVP-Server/gen-val/json-files> [outdir]
"""
import json
import os
import sys


def main():
    src = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "vectors"
    os.makedirs(out_dir, exist_ok=True)
    lines = {}

    kg = json.load(open(os.path.join(src, "ML-KEM-keyGen-FIPS203", "internalProjection.json")))
    for g in kg["testGroups"]:
        for t in g["tests"]:
            lines.setdefault(g["parameterSet"], []).append(
                f"keygen {t['tcId']} {t['d']} {t['z']} {t['ek']} {t['dk']}")

    ed = json.load(open(os.path.join(src, "ML-KEM-encapDecap-FIPS203", "internalProjection.json")))
    for g in ed["testGroups"]:
        ps, fn = g["parameterSet"], g["function"]
        for t in g["tests"]:
            if fn == "encapsulation":
                row = f"encaps {t['tcId']} {t['ek']} {t['m']} {t['c']} {t['k']}"
            elif fn == "decapsulation":
                kind = "valid" if t["reason"].startswith("valid") else "rejected"
                row = f"decaps {t['tcId']} {t['dk']} {t['c']} {t['k']} {kind}"
            elif fn == "encapsulationKeyCheck":
                row = f"ekcheck {t['tcId']} {t['ek']} {int(t['testPassed'])}"
            elif fn == "decapsulationKeyCheck":
                row = f"dkcheck {t['tcId']} {t['dk']} {int(t['testPassed'])}"
            else:
                raise ValueError(fn)
            lines.setdefault(ps, []).append(row)

    for ps, rows in sorted(lines.items()):
        path = os.path.join(out_dir, ps + ".txt")
        with open(path, "w") as f:
            f.write("\n".join(rows) + "\n")
        kinds = {}
        for r in rows:
            kinds[r.split()[0]] = kinds.get(r.split()[0], 0) + 1
        print(f"wrote {path}: {kinds}")


if __name__ == "__main__":
    main()
