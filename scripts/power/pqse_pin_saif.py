#!/usr/bin/env python3
"""pqse_pin_saif.py - turn the net activity of a gate-level dump into pin
activity for OpenSTA (make se-power-vcd / se-power-sample).

    python3 scripts/power/pqse_pin_saif.py <netlist.v> <dump.saif|dump.vcd> <out.saif>
        [--scope tb_pqse_gate/dut]

OpenSTA's read_saif / read_vcd annotate PINS (<instance>/<pin> below the
scope) and skip net names; a simulator dumps the netlist's nets (the cell
models' ports are not traced: that would multiply the simulation time and the
dump). This script reads the nets of the design instance (default: the
instance named "dut", wherever it is in the dump), maps every standard cell's
pin to the net bit it connects to (following the netlist's assign aliases),
and writes a SAIF with one INSTANCE per cell and its pins' T0 / T1 / TC, plus
the design's ports, under the same scope. A VCD is reduced to the same
toggle counts first (one pass; x / z count as 0).
"""
import argparse
import re
import sys

ID = r'[A-Za-z_][A-Za-z0-9_$]*'


# ---------------------------------------------------------------- netlist
def parse_netlist(path):
    """-> widths {name: (msb, lsb)}, cells [(type, inst, {pin: bit})],
    aliases [(bit, bit)], ports [names]"""
    text = open(path).read()
    m = re.search(r'\bmodule\s+pqse_top\b(.*?)\bendmodule\b', text, re.S)
    if not m:
        sys.exit('pqse_pin_saif: module pqse_top not found in %s' % path)
    body = re.sub(r'//[^\n]*|/\*.*?\*/', '', m.group(1), flags=re.S)
    widths, ports = {}, []
    for kind, rng, names in re.findall(r'\b(wire|input|output|inout|reg)\s+(\[\s*-?\d+\s*:\s*-?\d+\s*\])?\s*([^;]+);', body):
        msb = lsb = None
        if rng:
            a, b = re.findall(r'-?\d+', rng)
            msb, lsb = int(a), int(b)
        for n in names.split(','):
            n = n.strip()
            if re.fullmatch(ID, n):
                widths[n] = (msb, lsb)
                if kind in ('input', 'output', 'inout') and n not in ports:
                    ports.append(n)

    def bits(expr):
        """expression -> list of bit names (MSB first), None for constants"""
        expr = expr.strip()
        if expr.startswith('{') and expr.endswith('}'):
            out = []
            for part in split_concat(expr[1:-1]):
                out += bits(part)
            return out
        c = re.fullmatch(r"(\d+)'[sS]?([bBhHdDoO])([0-9a-fA-FxXzZ_?]+)", expr)
        if c:
            return [None] * int(c.group(1))
        c = re.fullmatch(r'(%s)\s*\[\s*(-?\d+)\s*:\s*(-?\d+)\s*\]' % ID, expr)
        if c:
            n, a, b = c.group(1), int(c.group(2)), int(c.group(3))
            step = -1 if a >= b else 1
            return ['%s[%d]' % (n, i) for i in range(a, b + step, step)]
        c = re.fullmatch(r'(%s)\s*\[\s*(-?\d+)\s*\]' % ID, expr)
        if c:
            return ['%s[%s]' % (c.group(1), c.group(2))]
        if re.fullmatch(ID, expr):
            msb, lsb = widths.get(expr, (None, None))
            if msb is None:
                return [expr]
            step = -1 if msb >= lsb else 1
            return ['%s[%d]' % (expr, i) for i in range(msb, lsb + step, step)]
        return []

    aliases = []
    for lhs, rhs in re.findall(r'\bassign\s+(.+?)\s*=\s*(.+?)\s*;', body, re.S):
        lb, rb = bits(lhs), bits(rhs)
        if len(lb) == len(rb):
            aliases += [(a, b) for a, b in zip(lb, rb) if a and b]

    cells = []
    for typ, inst, conns in re.findall(r'\b(%s)\s+(%s)\s*\(\s*(\..*?)\)\s*;' % (ID, ID), body, re.S):
        if not typ.startswith('sky130_'):
            continue                      # SRAM macros etc.: no power model
        pins = {}
        for pn, ex in re.findall(r'\.(%s)\s*\(([^()]*)\)' % ID, conns):
            b = bits(ex)
            if len(b) == 1 and b[0]:
                pins[pn] = b[0]
        cells.append((typ, inst, pins))
    return widths, cells, aliases, ports


def split_concat(s):
    out, depth, cur = [], 0, ''
    for ch in s:
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur)
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


# ---------------------------------------------------------------- dumps
def norm(name):
    """dump net name -> netlist bit name: 'x\\[3\\]' / 'x[3]' / 'x [3]' -> 'x[3]'"""
    return name.replace('\\', '').replace(' ', '')


def read_saif(path, scope):
    """-> (timescale string, duration, {bit name: (t0, t1, tc)}, scope used)"""
    ts, dur = '1ps', None
    stack, nets, found = [], {}, None
    inst_re = re.compile(r'^\s*\(INSTANCE\s+("?[^\s()"]+"?)')
    ent_re = re.compile(r'^\s*\((\S+)\s+\(T0\s+(\d+)\)\s*\(T1\s+(\d+)\).*?\(TC\s+(\d+)\)')
    with open(path) as f:
        for line in f:
            s = line.strip()
            m = re.match(r'\(TIMESCALE\s+([^)]*)\)', s)
            if m:
                ts = m.group(1).strip()
                continue
            m = re.match(r'\(DURATION\s+(\d+)', s)
            if m:
                dur = int(m.group(1))
                continue
            m = inst_re.match(line)
            if m:
                stack.append(('I', m.group(1).strip('"')))
                continue
            if s.startswith('(NET'):
                stack.append(('N', None))
                continue
            if s == ')':
                if stack:
                    stack.pop()
                continue
            m = ent_re.match(line)
            if m and stack and stack[-1][0] == 'N':
                path_ = '/'.join(n for k, n in stack if k == 'I')
                if found is None and (path_ == scope or (scope is None and path_.split('/')[-1] == 'dut')):
                    found = path_
                if path_ == found:
                    nets[norm(m.group(1))] = (int(m.group(2)), int(m.group(3)), int(m.group(4)))
    return ts, dur, nets, found


def read_vcd(path, scope):
    """VCD -> the same as read_saif (one pass over the value changes)"""
    stack, vars_, found = [], {}, None
    ts = '1ps'
    with open(path) as f:
        hdr = ''
        for line in f:
            if '$enddefinitions' in line:
                break
            hdr += line
            m = re.match(r'\s*\$scope\s+\S+\s+(\S+)\s+\$end', line)
            if m:
                stack.append(m.group(1))
                continue
            if re.match(r'\s*\$upscope', line):
                stack.pop()
                continue
            m = re.match(r'\s*\$var\s+\S+\s+(\d+)\s+(\S+)\s+(\S+)\s*(\[[^\]]*\])?\s*\$end', line)
            if m:
                path_ = '/'.join(stack)
                if found is None and (path_ == scope or (scope is None and stack and stack[-1] == 'dut')):
                    found = path_
                if path_ == found:
                    w, code, name, rng = int(m.group(1)), m.group(2), m.group(3), m.group(4)
                    if w == 1:
                        names = [norm(name + (rng or ''))]
                    else:
                        a, b = (re.findall(r'-?\d+', rng) + [w - 1, 0])[:2] if rng else (w - 1, 0)
                        a, b = int(a), int(b)
                        step = -1 if a >= b else 1
                        names = ['%s[%d]' % (name, i) for i in range(a, b + step, step)]
                    vars_.setdefault(code, []).append(names)
        m = re.search(r'\$timescale\s+(.*?)\s*\$end', hdr, re.S)
        if m:
            ts = m.group(1).strip()
        # per code: per bit (value, last change, high time, toggles)
        st = {c: [[0, None, 0, 0] for _ in range(len(v[0]))] for c, v in vars_.items()}
        t, t0 = 0, None
        for line in f:
            c0 = line[:1]
            if c0 == '#':
                t = int(line[1:])
                if t0 is None:
                    t0 = t
                continue
            if c0 in '01xzXZ':
                code, val = line[1:].strip(), line[0]
                bitsv = [val]
            elif c0 in 'bB':
                p = line[1:].split()
                if len(p) != 2:
                    continue
                val, code = p
                bitsv = list(val)
            else:
                continue
            s = st.get(code)
            if s is None:
                continue
            n = len(s)
            if len(bitsv) < n:
                pad = '0' if bitsv[0] in '01' else bitsv[0]
                bitsv = [pad] * (n - len(bitsv)) + bitsv
            for i in range(n):
                v = 1 if bitsv[i - n] == '1' else 0
                b = s[i]
                if b[1] is None:
                    b[0], b[1] = v, t
                elif v != b[0]:
                    if b[0]:
                        b[2] += t - b[1]
                    b[0], b[1] = v, t
                    b[3] += 1
        t_end = t
    if t0 is None:
        t0 = 0
    dur = t_end - t0
    nets = {}
    for code, namelists in vars_.items():
        for i, b in enumerate(st[code]):
            hi = b[2] + ((t_end - b[1]) if (b[1] is not None and b[0]) else 0)
            for names in namelists:
                nets[names[i]] = (dur - hi, hi, b[3])
    return ts, dur, nets, found


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('netlist')
    ap.add_argument('dump')
    ap.add_argument('out')
    ap.add_argument('--scope', default=None)
    a = ap.parse_args()
    scope = None if a.scope in (None, '', 'auto') else a.scope

    widths, cells, aliases, ports = parse_netlist(a.netlist)
    if re.search(r'\.vcd$', a.dump):
        ts, dur, nets, found = read_vcd(a.dump, scope)
    else:
        ts, dur, nets, found = read_saif(a.dump, scope)
    if found is None or not nets:
        sys.exit('pqse_pin_saif: no nets of %s in %s' % (scope or 'instance "dut"', a.dump))

    # alias groups (union-find): a pin's net may be dumped under another name
    parent = {}

    def root(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for x, y in aliases:
        rx, ry = root(x), root(y)
        if rx != ry:
            parent[rx] = ry
    act = {}
    for n, v in nets.items():
        act.setdefault(root(n), v)

    def lookup(bit):
        v = nets.get(bit)
        if v is None:
            v = act.get(root(bit))
        if v is None and bit.endswith('[0]'):
            v = nets.get(bit[:-3])           # a 1-bit vector dumped as a scalar
        if v is None and '[' not in bit:
            v = nets.get(bit + '[0]')
        return v

    npins = nfound = 0
    out = ['(SAIFILE', '(SAIFVERSION "2.0")', '(DIRECTION "backward")',
           '(PROGRAM_NAME "pqse_pin_saif.py")', '(DIVIDER / )',
           '(TIMESCALE %s)' % ts, '(DURATION %d)' % dur]
    levels = found.split('/')
    for i, n in enumerate(levels):
        out.append(' ' * i + '(INSTANCE %s' % n)
    ind = ' ' * len(levels)
    # the design's ports (top-level pins)
    pl = []
    for p in ports:
        msb, lsb = widths.get(p, (None, None))
        bl = [p] if msb is None else ['%s[%d]' % (p, i) for i in
                                      range(msb, lsb + (-1 if msb >= lsb else 1), -1 if msb >= lsb else 1)]
        for b in bl:
            v = lookup(b)
            if v:
                pl.append('%s (%s (T0 %d) (T1 %d) (TZ 0) (TX 0) (TB 0) (TC %d))'
                          % (ind + ' ', b.replace('[', '\\[').replace(']', '\\]'), v[0], v[1], v[2]))
    if pl:
        out += [ind + '(NET'] + pl + [ind + ')']
    for typ, inst, pins in cells:
        ents = []
        for pn, bit in pins.items():
            npins += 1
            v = lookup(bit)
            if v is None:
                continue
            nfound += 1
            ents.append('%s  (%s (T0 %d) (T1 %d) (TZ 0) (TX 0) (TB 0) (TC %d))' % (ind, pn, v[0], v[1], v[2]))
        if ents:
            out += ['%s(INSTANCE %s' % (ind, inst), '%s (NET' % ind] + ents + ['%s )' % ind, '%s)' % ind]
    for i in range(len(levels) - 1, -1, -1):
        out.append(' ' * i + ')')
    out.append(')')
    with open(a.out, 'w') as f:
        f.write('\n'.join(out) + '\n')
    share = 100.0 * nfound / npins if npins else 0.0
    print('pqse_pin_saif: %s: %d nets of %s, %d cells, %d of %d pins with activity (%.1f %%) -> %s'
          % (a.dump, len(nets), found, len(cells), nfound, npins, share, a.out))
    if share < 90:
        print('pqse_pin_saif: WARNING: many pins without a dumped net (constant ties are normal; '
              'more means the dump lacks nets)')


if __name__ == '__main__':
    main()
