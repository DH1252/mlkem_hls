#!/usr/bin/env python3
"""pqse_sram_char.py - energy per access of the PQSE SRAM shapes from OpenRAM's
SPICE-characterized Liberty files, as the table scripts/power/pqse_energy.py
reads (--sram-table; make se-sram-char writes it, se-power-vcd uses it with
SRAM_TABLE=...).

    python3 scripts/power/pqse_sram_char.py <lib> [<lib> ...] [-o sram_table.txt]

What OpenRAM writes (compiler/characterizer/lib.py, delay.py): under each
clock pin, internal_power groups with a "when" condition - write (csb low, web
low), read (csb low, web high, or a read-only port), and the same with csb high
(port deselected). Their rise / fall values are the AVERAGE POWER in mW over
one clock cycle of the SPICE simulation (power_measure, scaled x 1e3), with
the data bit 1 / 0, measured at the minimum period the characterizer found
(written as the clock pin's minimum_period constraint, in the library's
time unit). So the energy of one access is

    E [pJ] = mean(rise, fall) [mW] x min_period [ns]

and of one clock of a deselected port the same with the csb-high values. The
leakage is cell_leakage_power (in leakage_power_unit).

Port mapping (pqse_ram_1r1w: one write port, one read port): a port with a din
bus writes, one with a dout bus reads (a rw port has both, selected by web).
The write energy is that of the writing port enabled for a write, the read
energy that of the read-only port (1rw1r: port 1; 1r1w: the read port). The
idle energy per clock is, per port, the mean of its deselected values, summed
over the ports (each port has its own clock pin, and both tick).

Output lines: <shape> <pJ per read> <pJ per write> <leakage uW> <pJ per idle clock>
with the shape from the file name (pqse_sram_a<AW>_d<DW>...). The idle energy
counts only with pqse_energy.py --sram-idle-clocked (the macro's clock not gated
while it is not accessed).

A library from the ANALYTICAL model (analytical_delay = True, OpenRAM's
default; e.g. the published sky130_sram_macros; make se-sram-char
OR_ANALYTICAL=1) has one value for every condition: it is rejected unless
--allow-analytical is given. That value is not measured over a clock period:
it is the sum of C V^2 f over the blocks at the technology's event frequency
(compiler/characterizer/elmore.py; sky130 tech.py default_event_frequency =
100 MHz), so the energy per access is

    E [pJ] = P [mW] / f_event = P [mW] x 1e3 / f_event [MHz]

for read and write alike (--event-mhz, default 100), and the idle energy is
written as 0 (the model has none).
"""
import argparse
import os
import re
import sys

UNIT = {'f': 1e-15, 'p': 1e-12, 'n': 1e-9, 'u': 1e-6, 'm': 1e-3, '': 1.0}


def unit_scale(text, what, default):
    """'1mW' -> 1e-3, '1ns' -> 1e-9 (relative to W / s)"""
    m = re.search(r'%s\s*:\s*"?\s*([0-9.]+)\s*([fpnum]?)[A-Za-z]*\s*"?' % what, text)
    if not m:
        return default
    return float(m.group(1)) * UNIT[m.group(2)]


def groups(text, name):
    """every '<name> ( ... ) { ... }' group: (argument, body), braces matched"""
    out = []
    for m in re.finditer(r'\b%s\s*\(\s*([^)]*)\)\s*\{' % name, text):
        depth, i = 1, m.end()
        while depth and i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
            i += 1
        out.append((m.group(1).strip().strip('"'), text[m.end():i - 1]))
    return out


def first_value(body):
    m = re.search(r'values\s*\(\s*"([^"]*)"', body)
    if not m:
        return None
    return [float(x) for x in m.group(1).replace(',', ' ').split()]


def parse_lib(path):
    text = open(path).read()
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    t_scale = unit_scale(text, 'time_unit', 1e-9)
    leak_scale = unit_scale(text, 'leakage_power_unit', 1e-3)
    m = re.search(r'cell_leakage_power\s*:\s*([0-9.eE+-]+)', text)
    leak_w = float(m.group(1)) * leak_scale if m else 0.0
    m = re.search(r'\barea\s*:\s*([0-9.eE+-]+)', text)
    area = float(m.group(1)) if m else None
    ports = {}
    writes = set(int(x) for x in re.findall(r'\bbus\s*\(\s*din(\d+)\s*\)', text))
    reads = set(int(x) for x in re.findall(r'\bbus\s*\(\s*dout(\d+)\s*\)', text))
    for pname, body in groups(text, 'pin'):
        if not re.match(r'clk\d+$', pname):
            continue
        port = int(pname[3:])
        per = None
        for _, tb in groups(body, 'timing'):
            if re.search(r'timing_type\s*:\s*"?minimum_period', tb):
                v = []
                for _, cb in groups(tb, 'rise_constraint') + groups(tb, 'fall_constraint'):
                    v += first_value(cb) or []
                if v:
                    per = max(v) * t_scale
        conds = {}
        for _, pb in groups(body, 'internal_power'):
            m = re.search(r'when\s*:\s*"([^"]*)"', pb)
            when = re.sub(r'\s+', '', m.group(1)) if m else ''
            r = [first_value(b) for _, b in groups(pb, 'rise_power')]
            f = [first_value(b) for _, b in groups(pb, 'fall_power')]
            vals = [x[0] for x in r + f if x]
            if vals:
                conds[when] = sum(vals) / len(vals)          # mW: mean of data 1 / data 0
        ports[port] = (per, conds)
    return dict(path=path, ports=ports, writes=writes, reads=reads, leak_w=leak_w, area=area)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('libs', nargs='+')
    ap.add_argument('-o', '--out')
    ap.add_argument('--allow-analytical', action='store_true')
    ap.add_argument('--event-mhz', type=float, default=100.0,
                    help='event frequency of the analytical model (sky130: 100)')
    a = ap.parse_args()

    lines, bad = [], 0
    print('%-9s %8s %9s %9s %9s %9s %10s %12s  %s' % ('shape', 'period', 'pJ/read', 'pJ/write',
                                                     'pJ/idle', 'leak uW', 'area mm2', 'model', 'file'))
    for path in a.libs:
        m = re.search(r'(a\d+_d\d+)', os.path.basename(path))
        if not m:
            print('pqse_sram_char: %s: no shape a<AW>_d<DW> in the file name, skipped' % path)
            continue
        shape = m.group(1)
        lib = parse_lib(path)
        if not lib['ports']:
            print('pqse_sram_char: %s: no clock pin with internal_power, skipped' % path)
            bad += 1
            continue
        # a port with din writes, one with dout reads (rw: both, selected by web).
        # Write energy: the writing port enabled with a write; read energy: the
        # read-only port if there is one (pqse_ram_1r1w reads there), else the rw
        # port enabled with web high. Idle: per port the mean of its deselected
        # (csb high) values, summed over the ports (every port's clock ticks)
        e_wr = e_rd = e_rd_rw = None
        e_idle, allv, period = 0.0, [], None
        ro = [p for p in lib['reads'] if p not in lib['writes']]
        for port, (per, conds) in sorted(lib['ports'].items()):
            if per is None:
                continue
            period = per if period is None else max(period, per)
            allv += list(conds.values())
            pj = lambda v: v * 1e-3 * per * 1e12             # mW x s -> pJ
            wr, rd = port in lib['writes'], port in lib['reads']
            idle = []
            for when, v in conds.items():
                en = ('!csb%d' % port) in when
                if not en:
                    idle.append(pj(v))
                elif wr and rd:
                    if ('!web%d' % port) in when:
                        e_wr = pj(v)
                    else:
                        e_rd_rw = pj(v)
                elif wr:
                    e_wr = pj(v)
                elif rd:
                    e_rd = pj(v)
            if idle:
                e_idle += sum(idle) / len(idle)
        if not ro:
            e_rd = e_rd_rw
        if period is None or e_wr is None or e_rd is None:
            print('pqse_sram_char: %s: could not find the minimum period or the read / write '
                  'powers, skipped' % path)
            bad += 1
            continue
        analytical = len(set(round(v, 9) for v in allv)) <= 1
        model = 'ANALYTICAL' if analytical else 'spice'
        area = '%.4f' % (lib['area'] * 1e-6) if lib['area'] else '-'
        print('%-9s %6.2fns %9.2f %9.2f %9.2f %9.2f %10s %12s  %s' % (
            shape, period * 1e9, e_rd, e_wr, e_idle, lib['leak_w'] * 1e6, area, model, path))
        if analytical and not a.allow_analytical:
            print('  -> rejected: an analytical-model library (one value for read, write and '
                  'deselected); characterize with analytical_delay = False, or --allow-analytical')
            bad += 1
            continue
        if analytical:
            # one C V^2 f power at the event frequency, not a per-cycle average
            e_rd = e_wr = allv[0] * 1e3 / a.event_mhz
            e_idle = 0.0
            model = 'analytical@%gMHz' % a.event_mhz
            print('  -> analytical: %.2f pJ per read / write (%.4f mW / %g MHz), no idle energy'
                  % (e_rd, allv[0], a.event_mhz))
        lines.append('%s %.4f %.4f %.4f %.4f   # %s, %s, min period %.3f ns' % (
            shape, e_rd, e_wr, lib['leak_w'] * 1e6, e_idle, os.path.basename(path), model,
            period * 1e9))
    if a.out and lines:
        with open(a.out, 'w') as f:
            f.write('# <shape> <pJ per read> <pJ per write> <leakage uW> <pJ per idle clock>\n')
            f.write('# from OpenRAM Liberty files (scripts/power/pqse_sram_char.py)\n')
            f.write('\n'.join(lines) + '\n')
        print('wrote %s (%d shapes)' % (a.out, len(lines)))
    if bad:
        sys.exit(1)


if __name__ == '__main__':
    main()
