#!/usr/bin/env python3
"""pqse_energy.py - energy per command from the gate-level power run of
make se-power-vcd (scripts/pqse_power.tcl report + tb_pqse_gate.sv results).

    python3 scripts/power/pqse_energy.py <power report> --run gl_run.txt
        [--dump gate.saif|gate.vcd] [--sram sram_access.txt]
        [--command-clocks N] [--card-mhz 3.39]
        [--epb-rd 0.5] [--epb-wr 0.8] [--e0 2.0] [--sram-table <file>]
        [--sram-leak-uw 0]

Logic: OpenSTA's average power over the dump (toggle counts divided by the
dump's time span) times that span is the energy of the window: exactly the
sum of every pin's toggles times its Liberty energy, plus the leakage. The
span is the one OpenSTA divides by: DURATION x TIMESCALE of a SAIF, last minus
first time stamp of a VCD (without --dump: window clocks x period).

SRAM macros (RAM_MACRO=1): no power in their Liberty stub; their energy comes
from the access counts the macro models recorded inside the window,
    E = reads x (E0 + DW x EPB_RD) + writes x (E0 + DW x EPB_WR)
The defaults (E0 2 pJ, 0.5 / 0.8 pJ per bit read / written) are a first-order
guess for small 130 nm, 1.8 V macros, NOT a datasheet: --sram-table <file>
with lines "<shape> <pJ per read> <pJ per write> [leakage uW]" (shape as
a<AW>_d<DW>, e.g. a10_d16) replaces them with the SRAM compiler's numbers.

Card clock: the Liberty internal and switching energies are per transition,
so the energy per clock does not depend on the clock frequency (same voltage):
the power at the card clock is the dynamic energy per clock x f + leakage.
"""
import argparse
import os
import re
import sys

GROUPS = ('Sequential', 'Combinational', 'Clock', 'Macro', 'Pad', 'Total')
NUM = r'([-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?)'
UNITS = {'s': 1.0, 'ms': 1e-3, 'us': 1e-6, 'ns': 1e-9, 'ps': 1e-12, 'fs': 1e-15}


def parse_power(path):
    """Group rows of report_power: name -> (internal, switching, leakage, total) W,
    and the annotation counts of report_activity_annotation."""
    groups, annot = {}, {}
    row = re.compile(r'^\s*(%s)\s+%s\s+%s\s+%s\s+%s' % ('|'.join(GROUPS), NUM, NUM, NUM, NUM))
    ann = re.compile(r'^\s*(vcd|saif|input|user|unannotated)\s+(\d+)\s*$')
    with open(path) as f:
        for line in f:
            m = row.match(line)
            if m and m.group(1) not in groups:
                groups[m.group(1)] = tuple(float(m.group(i)) for i in range(2, 6))
                continue
            m = ann.match(line)
            if m:
                annot[m.group(1)] = int(m.group(2))
    if 'Total' not in groups:
        sys.exit('pqse_energy: no "Total" power row in %s (did OpenSTA fail?)' % path)
    return groups, annot


def parse_kv(path):
    d = {}
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) >= 2:
                try:
                    d[p[0]] = float(p[1])
                except ValueError:
                    d[p[0]] = p[1]
    return d


def timescale(s):
    m = re.match(r'\s*(\d+(?:\.\d+)?)\s*([munpf]?s)\s*$', s)
    if not m:
        return None
    return float(m.group(1)) * UNITS[m.group(2)]


def saif_span(path):
    """DURATION x TIMESCALE (s) of a SAIF; Verilator writes both before the
    instance data, the standard header has them too."""
    dur = ts = None
    opener = open
    if path.endswith('.gz'):
        import gzip
        opener = gzip.open
    with opener(path, 'rt') as f:
        for k, line in enumerate(f):
            m = re.search(r'\(\s*TIMESCALE\s+([^)]*)\)', line)
            if m:
                ts = timescale(m.group(1))
            m = re.search(r'\(\s*DURATION\s+(\d+(?:\.\d+)?)\s*\)', line)
            if m:
                dur = float(m.group(1))
            if (dur is not None and ts is not None) or k > 200000:
                break
    if dur is None or ts is None:
        return None
    return dur * ts


def vcd_span(path):
    """last minus first time stamp x timescale (s) of a VCD."""
    ts = None
    first = None
    hdr = ''
    with open(path, 'rb') as f:
        for raw in f:
            line = raw.decode('ascii', 'replace')
            if ts is None:
                hdr += line
                m = re.search(r'\$timescale\s+(.*?)\s*\$end', hdr, re.S)
                if m:
                    ts = timescale(m.group(1))
                    hdr = ''
            if line.startswith('#'):
                try:
                    first = int(line[1:].split()[0])
                    break
                except (ValueError, IndexError):
                    pass
        size = os.path.getsize(path)
        f.seek(max(0, size - (1 << 20)))
        tail = f.read().decode('ascii', 'replace').splitlines()
    last = None
    for line in reversed(tail):
        if line.startswith('#'):
            try:
                last = int(line[1:].split()[0])
                break
            except (ValueError, IndexError):
                pass
    if ts is None or first is None or last is None:
        return None
    return (last - first) * ts


def parse_sram(path):
    """shape -> [reads, writes], summed over the macro instances."""
    acc = {}
    if not path or not os.path.exists(path):
        return acc
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) == 3 and re.fullmatch(r'a\d+_d\d+', p[0]):
                a = acc.setdefault(p[0], [0, 0, 0])
                a[0] += int(p[1])
                a[1] += int(p[2])
                a[2] += 1
    return acc


def parse_table(path):
    t = {}
    with open(path) as f:
        for line in f:
            line = line.split('#')[0].split()
            if len(line) >= 3:
                t[line[0]] = (float(line[1]), float(line[2]),
                              float(line[3]) if len(line) > 3 else 0.0)
    return t


def eng(x, unit):
    """engineering notation: 1.23e-6 J -> '1.230 uJ'"""
    if x == 0:
        return '0 %s' % unit
    for p, s in ((1e0, ''), (1e-3, 'm'), (1e-6, 'u'), (1e-9, 'n'), (1e-12, 'p'), (1e-15, 'f')):
        if abs(x) >= p:
            return '%.3f %s%s' % (x / p, s, unit)
    return '%.3e %s' % (x, unit)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('power')
    ap.add_argument('--run', required=True)
    ap.add_argument('--dump')
    ap.add_argument('--sram')
    ap.add_argument('--command-clocks', type=int, default=0)
    ap.add_argument('--card-mhz', type=float, default=3.39)
    ap.add_argument('--epb-rd', type=float, default=0.5)
    ap.add_argument('--epb-wr', type=float, default=0.8)
    ap.add_argument('--e0', type=float, default=2.0)
    ap.add_argument('--sram-table')
    ap.add_argument('--sram-leak-uw', type=float, default=0.0)
    a = ap.parse_args()

    groups, annot = parse_power(a.power)
    run = parse_kv(a.run)
    period = run.get('period_ns', 20.0) * 1e-9
    nclk = int(run.get('window_clocks', 0))
    full = int(run.get('full', 0)) == 1
    cmd = int(run.get('cmd', 0))
    if nclk <= 0:
        sys.exit('pqse_energy: no window_clocks in %s' % a.run)

    # ---- the time span OpenSTA averaged over
    span = None
    if a.dump and os.path.exists(a.dump):
        span = saif_span(a.dump) if re.search(r'\.saif(\.gz)?$', a.dump) else vcd_span(a.dump)
    span_note = 'dump time span'
    if span is None or span <= 0:
        span = nclk * period
        span_note = 'window clocks x period (dump span not found)'

    print('PQSE energy (sky130_fd_sc_hd, tt 25C 1.8 V), command %d' % cmd)
    print('=' * 72)
    tot = annot.get('vcd', 0) + annot.get('saif', 0)
    una = annot.get('unannotated', 0)
    if tot or una:
        share = tot / float(tot + una) if tot + una else 0.0
        print('annotated pins     %d of %d (%.1f %%)' % (tot, tot + una, 100 * share))
        if share < 0.8:
            print('WARNING: under 80 %% of the pins carry simulated activity - the rest is '
                  'propagated (a SCOPE mismatch, or a dump without the cell pins)')
    print('window             %d clocks (%s)%s' % (nclk, eng(nclk * period, 's'),
                                                  ', the whole command' if full else ''))
    if abs(span - nclk * period) > 0.02 * nclk * period:
        print('NOTE: the dump spans %s, the window %s; energies use the dump span '
              '(what OpenSTA divided by)' % (eng(span, 's'), eng(nclk * period, 's')))
    print('span used          %s (%s)' % (eng(span, 's'), span_note))

    # ---- logic
    print('\nlogic (OpenSTA, average over the window, x span)')
    print('  %-14s %12s %12s %12s %12s' % ('group', 'internal', 'switching', 'leakage', 'energy'))
    for g in GROUPS:
        if g in groups:
            i, s, l, t = groups[g]
            print('  %-14s %12s %12s %12s %12s' % (g, eng(i, 'W'), eng(s, 'W'), eng(l, 'W'),
                                                  eng(t * span, 'J')))
    i, s, l, t = groups['Total']
    e_dyn = (i + s) * span
    e_leak = l * span

    # ---- SRAM macros
    acc = parse_sram(a.sram)
    table = parse_table(a.sram_table) if a.sram_table else {}
    e_sram = 0.0
    p_sram_leak = a.sram_leak_uw * 1e-6
    if acc:
        print('\nSRAM macros (access counts in the window x energy per access)')
        print('  %-9s %5s %12s %12s %10s %10s %12s' % ('shape', 'inst', 'reads', 'writes',
                                                     'pJ/read', 'pJ/write', 'energy'))
        for shape in sorted(acc):
            nr, nw, ninst = acc[shape]
            dw = int(shape.split('_d')[1])
            if shape in table:
                er, ew, lk = table[shape]
                p_sram_leak += lk * 1e-6 * ninst
            else:
                er = a.e0 + dw * a.epb_rd
                ew = a.e0 + dw * a.epb_wr
            e = (nr * er + nw * ew) * 1e-12
            e_sram += e
            print('  %-9s %5d %12d %12d %10.2f %10.2f %12s' % (shape, ninst, nr, nw, er, ew, eng(e, 'J')))
        src = 'table %s' % a.sram_table if table else \
            'E0 %.2f pJ + %.2f / %.2f pJ per bit read / written - an assumption' % (a.e0, a.epb_rd, a.epb_wr)
        print('  (%s)' % src)
    elif a.sram:
        print('\nSRAM macros: no access counts (%s empty: RAM_MACRO=0 builds the RAMs from '
              'flip-flops, inside the logic numbers)' % a.sram)
    e_sram_leak = p_sram_leak * span

    # ---- totals over the window
    e_win = e_dyn + e_leak + e_sram + e_sram_leak
    print('\nwindow total       %s  (logic dynamic %s, logic leakage %s, SRAM %s%s)' % (
        eng(e_win, 'J'), eng(e_dyn, 'J'), eng(e_leak, 'J'), eng(e_sram, 'J'),
        ', SRAM leakage %s' % eng(e_sram_leak, 'J') if e_sram_leak else ''))
    e_clk_dyn = (e_dyn + e_sram) / nclk
    print('per clock          %s dynamic' % eng(e_clk_dyn, 'J'))
    print('average power      %s at %.1f MHz' % (eng(e_win / span, 'W'), 1e-6 / period))

    # ---- per command
    if full:
        ncmd = nclk
        e_cmd_dyn = e_dyn + e_sram
        how = 'measured'
    elif a.command_clocks:
        ncmd = a.command_clocks
        e_cmd_dyn = e_clk_dyn * ncmd
        how = 'extrapolated from the window (%d of %d clocks)' % (nclk, ncmd)
    else:
        ncmd = 0
    p_leak = l + p_sram_leak
    print('\nper command (%s)' % ('KeyGen' if cmd == 1 else 'Encaps' if cmd == 2 else
                                'Decaps' if cmd == 3 else 'command %d' % cmd))
    if ncmd:
        f_card = a.card_mhz * 1e6
        for f, name in ((1.0 / period, '%.1f MHz' % (1e-6 / period)),
                        (f_card, '%.2f MHz card clock' % a.card_mhz)):
            t_cmd = ncmd / f
            e_cmd = e_cmd_dyn + p_leak * t_cmd
            print('  %-22s %10d clocks  %12s  %12s  avg %s' % (
                name, ncmd, eng(t_cmd, 's'), eng(e_cmd, 'J'), eng(e_cmd / t_cmd, 'W')))
        print('  (%s; leakage scales with the run time, the dynamic energy does not)' % how)
    else:
        print('  a window only: pass --command-clocks <clocks of the command> '
              '(make ... GL_CLOCKS=<n>; make sim-se prints them) to extrapolate')


if __name__ == '__main__':
    main()
