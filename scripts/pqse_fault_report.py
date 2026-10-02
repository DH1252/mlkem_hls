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
            runs.append((tgt, int(bit), int(word), int(clk), res, cls))
    if not runs:
        sys.exit('pqse_fault_report: no runs in %s' % a.log)

    classes = ['unchanged', 'detected', 'rejection', 'SILENT', 'hang']
    tot = defaultdict(int)
    per = defaultdict(lambda: defaultdict(int))
    for tgt, bit, word, clk, res, cls in runs:
        tot[cls] += 1
        per[tgt][cls] += 1
    n = len(runs)
    print('fault campaign: %s, %d runs (one bit flip each, random target / bit / clock)' % (op, n))
    print('=' * 78)
    for c in classes:
        print('  %-10s %6d  %5.1f %%' % (c, tot[c], 100.0 * tot[c] / n))
    eff = n - tot['unchanged']
    if eff:
        safe = tot['detected'] + tot['rejection']
        print('\nof the %d runs where the fault had an effect: %.1f %% detected or rejected, '
              '%d silent, %d hangs' % (eff, 100.0 * safe / eff, tot['SILENT'], tot['hang']))
    print('\nper target:')
    print('  %-16s %5s %10s %9s %10s %7s %5s' % ('target', 'runs', 'unchanged', 'detected',
                                                 'rejection', 'SILENT', 'hang'))
    for tgt in sorted(per, key=lambda t: (-per[t]['SILENT'], -per[t]['hang'], t)):
        d = per[tgt]
        print('  %-16s %5d %10d %9d %10d %7d %5d' % (tgt, sum(d.values()), d['unchanged'],
              d['detected'], d['rejection'], d['SILENT'], d['hang']))
    sil = [r for r in runs if r[5] == 'SILENT']
    if sil:
        print('\nsilent runs (target bit word clock):')
        for tgt, bit, word, clk, res, cls in sil[:40]:
            print('  %-16s %4d %4d %8d' % (tgt, bit, word, clk))
    print('\nRESULT: %s' % ('no silent fault' if not sil else '%d silent fault(s)' % len(sil)))


if __name__ == '__main__':
    main()
