#!/usr/bin/env python3
"""pqse_ff_report.py - which flip-flops of the sky130 netlist are clocked every
cycle (not behind a clock gate), by RTL register (make se-power).

    python3 scripts/power/pqse_ff_report.py <netlist.v> [--clock clk] [--top 40]

Reads the netlist make se-power writes (build/sepower/pqse_top_sky130.v: the
Yosys names are kept, unlike the enumerated gate-level netlist). A flip-flop
whose clock pin is on the clock port itself is clocked in every cycle: its
clock-pin energy (~2 uW per flip-flop at 50 MHz in sky130_fd_sc_hd) is spent
whether it changes or not. They are grouped by the register their Q output
drives (the RTL name, bit index dropped), largest first; flip-flops on a
clock gate's output are counted per gate. A register listed here has no
enable at all (loaded every clock), or a group smaller than CG_MIN.
"""
import argparse
import re
import sys
from collections import defaultdict

ID = r'(?:\\\S+|[A-Za-z_][A-Za-z0-9_$]*)'


def norm(e):
    """netlist expression -> plain name: '\\u_sys.x [3]' -> 'u_sys.x[3]'"""
    e = e.strip()
    if e.startswith('\\'):
        e = e[1:]
    return re.sub(r'\s+', '', e)


def base(n):
    return re.sub(r'\[\d+\]$', '', n)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('netlist')
    ap.add_argument('--clock', default='clk')
    ap.add_argument('--top', type=int, default=40)
    a = ap.parse_args()

    text = open(a.netlist).read()
    m = re.search(r'\bmodule\s+pqse_top\b(.*?)\bendmodule\b', text, re.S)
    if not m:
        sys.exit('pqse_ff_report: module pqse_top not found in %s' % a.netlist)
    body = m.group(1)

    # assign aliases: auto-named nets (_123_) -> a readable name
    alias = {}
    for lhs, rhs in re.findall(r'\bassign\s+(%s(?:\s*\[\d+\])?)\s*=\s*(%s(?:\s*\[\d+\])?)\s*;' % (ID, ID), body):
        l, r = norm(lhs), norm(rhs)
        for x, y in ((r, l), (l, r)):
            if x.startswith('_') and not y.startswith('_'):
                alias.setdefault(x, y)

    def readable(n):
        if not n.startswith('_'):
            return n
        return alias.get(n, n)

    cell_re = re.compile(r'\b(sky130_fd_sc_\w+)\s+(%s)\s*\((.*?)\)\s*;' % ID, re.S)
    pin_re = re.compile(r'\.(\w+)\s*\(\s*([^()]*?)\s*\)')
    gates = {}                  # gated clock net -> ICG enable net
    ffs = []                    # (type, clock net, Q net)
    for typ, inst, conns in cell_re.findall(body):
        pins = {p: norm(e) for p, e in pin_re.findall(conns)}
        if 'dlclkp' in typ or 'sdlclkp' in typ:
            if 'GCLK' in pins:
                gates[pins['GCLK']] = readable(pins.get('GATE', '?'))
            continue
        if 'CLK' in pins and ('Q' in pins or 'Q_N' in pins) and re.search(r'__(e?df|dfx|dfr|dfs|dfb|sdf)', typ):
            q = pins.get('Q') or pins.get('Q_N')
            ffs.append((typ, pins['CLK'], readable(q)))

    ungated = defaultdict(int)
    gated = defaultdict(int)
    other = defaultdict(int)
    for typ, ck, q in ffs:
        if ck == a.clock:
            ungated[base(q)] += 1
        elif ck in gates:
            gated[ck] += 1
        else:
            other[ck] += 1
    nu, ng, no = sum(ungated.values()), sum(gated.values()), sum(other.values())
    print('flip-flops: %d; on the bare clock (clocked every cycle): %d; behind %d clock gates: %d; '
          'other clocks: %d' % (len(ffs), nu, len(gates), ng, no))
    print('\nclocked every cycle, by register (bits), largest first:')
    for n, c in sorted(ungated.items(), key=lambda kv: (-kv[1], kv[0]))[:a.top]:
        print('  %5d  %s' % (c, n))
    rest = sorted(ungated.items(), key=lambda kv: (-kv[1], kv[0]))[a.top:]
    if rest:
        print('  %5d  (%d more registers)' % (sum(c for _, c in rest), len(rest)))
    if other:
        print('\nother clocks:')
        for n, c in sorted(other.items(), key=lambda kv: -kv[1])[:10]:
            print('  %5d  %s' % (c, n))


if __name__ == '__main__':
    main()
