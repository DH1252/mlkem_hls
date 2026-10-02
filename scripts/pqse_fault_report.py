#!/usr/bin/env python3
"""pqse_fault_report.py - summary of a fault-injection campaign
(make sim-se-fault, hw/sim/tb_pqse_fault.sv).

    python3 scripts/pqse_fault_report.py <fault_log.txt> [--vectors hw/sim/vectors]

Every run flipped one bit of one target at a random clock of the command.
Outcomes:
  unchanged   the output is right (the fault hit nothing live, or was masked)
  detected    the command ended with an error result (8 FAULT, 7 KILLED, ...):
              the engines were reset and the keys wiped
  rejection   Decaps returned the implicit-rejection key K' = J(z || c) =
              SHAKE256(z || c, 32): the re-encryption check caught the fault;
              harmless (K' carries nothing about the secret key)
  SILENT      a different output with result 0: KeyGen gave a wrong ek, or
              Decaps a K that is neither K nor K' - the fault reached the
              outside unnoticed (the case fault attacks exploit)
  hang        no done within the time limit (the host can only reset)
Also counted: runs in which the PRNG handed out a random word twice (r=1:
masks reused, the masking weakened for that run - not visible in the output).
Target "none" flips nothing (null control): it must always come out unchanged;
otherwise the harness, not the design, is wrong and nothing else counts.
"""
import argparse
import hashlib
import os
import sys
from collections import defaultdict


def hexfile(path):
    with open(path) as f:
        return bytes(int(l.strip(), 16) for l in f if l.strip())


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('log')
    ap.add_argument('--vectors', default='hw/sim/vectors')
    a = ap.parse_args()

    k_rej = None
    dkp = os.path.join(a.vectors, 'de0_dk.hex')
    cp = os.path.join(a.vectors, 'de0_c.hex')
    if os.path.exists(dkp) and os.path.exists(cp):
        z = hexfile(dkp)[2368:2400]
        c = hexfile(cp)
        k_rej = hashlib.shake_256(z + c).digest(32).hex()

    op, runs = '?', []
    with open(a.log) as f:
        for line in f:
            p = line.split()
            if not p:
                continue
            if p[0] == '#':
                if 'op' in p:
                    op = p[p.index('op') + 1]
                continue
            run, tgt, bit, word, clk, res, oc = p[:7]
            reuse = len(p) > 7 and p[7] == 'r=1'
            res = int(res)
            if oc == 'hang':
                cls = 'hang'
            elif res != 0:
                cls = 'detected'
            elif oc == 'ok':
                cls = 'unchanged'
            elif oc.startswith('K=') and k_rej and oc[2:].lower() == k_rej:
                cls = 'rejection'
            else:
                cls = 'SILENT'
            runs.append((tgt, int(bit), int(word), int(clk), res, cls, reuse))
    if not runs:
        sys.exit('pqse_fault_report: no runs in %s' % a.log)

    classes = ['unchanged', 'detected', 'rejection', 'SILENT', 'hang']
    tot = defaultdict(int)
    per = defaultdict(lambda: defaultdict(int))
    nre = 0
    for tgt, bit, word, clk, res, cls, reuse in runs:
        tot[cls] += 1
        per[tgt][cls] += 1
        if reuse:
            nre += 1
            per[tgt]['reuse'] += 1
    nul = [r for r in runs if r[0] == 'none']
    nul_bad = [r for r in nul if r[5] != 'unchanged']
    n = len(runs)
    print('fault campaign: %s, %d runs (one bit flip each, random target / bit / clock)' % (op, n))
    print('=' * 78)
    for c in classes:
        print('  %-10s %6d  %5.1f %%' % (c, tot[c], 100.0 * tot[c] / n))
    print('  %-10s %6d  (PRNG word handed out twice: masks reused)' % ('PRNG reuse', nre))
    print('  null control ("none", no fault): %d runs, %d not unchanged' % (len(nul), len(nul_bad)))
    if nul_bad:
        print('\nHARNESS ERROR: runs without a fault gave a different result - the counts '
              'above are not about the design')
    eff = n - tot['unchanged']
    if eff:
        safe = tot['detected'] + tot['rejection']
        print('\nof the %d runs where the fault had an effect: %.1f %% detected or rejected, '
              '%d silent, %d hangs' % (eff, 100.0 * safe / eff, tot['SILENT'], tot['hang']))
    print('\nper target:')
    print('  %-16s %5s %10s %9s %10s %7s %5s %6s' % ('target', 'runs', 'unchanged', 'detected',
                                                     'rejection', 'SILENT', 'hang', 'reuse'))
    for tgt in sorted(per, key=lambda t: (-per[t]['SILENT'], -per[t]['hang'], t)):
        d = per[tgt]
        print('  %-16s %5d %10d %9d %10d %7d %5d %6d' % (tgt, sum(d[c] for c in classes), d['unchanged'],
              d['detected'], d['rejection'], d['SILENT'], d['hang'], d['reuse']))
    sil = [r for r in runs if r[5] == 'SILENT']
    if sil:
        print('\nsilent runs (target bit word clock):')
        for tgt, bit, word, clk, res, cls, reuse in sil[:40]:
            print('  %-16s %4d %4d %8d' % (tgt, bit, word, clk))
    if nul_bad:
        print('\nRESULT: harness error (null control failed)')
    else:
        print('\nRESULT: %s, %d PRNG reuse(s)' % ('no silent fault' if not sil else
                                                 '%d silent fault(s)' % len(sil), nre))


if __name__ == '__main__':
    main()
