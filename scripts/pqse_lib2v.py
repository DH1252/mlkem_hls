#!/usr/bin/env python3
"""pqse_lib2v.py - behavioural Verilog models of standard cells from a Liberty
file, for a fast zero-delay gate-level simulation of a mapped netlist (make
se-power-vcd).

  python3 scripts/pqse_lib2v.py <cells.lib> <netlist.v> <out.v>

Only the cells the netlist instantiates are written. Each model follows the
Liberty description:
  - output pins with a "function": continuous assignments
  - ff ("IQ", "IQ_N") groups: an edge-triggered register (clocked_on,
    next_state, asynchronous clear / preset), initial value 0
  - latch ("IQ", "IQ_N") groups: a level-sensitive latch (enable, data_in,
    clear / preset), initial value 0
  - three_state outputs: function when enabled, else z
  - integrated clock-gating cells (clock_gating_integrated_cell, e.g. the
    dlclkp the Yosys clockgate pass inserts): the enable pins are captured by a
    latch while the clock is low, the gated clock is clock AND latch ("latch_
    posedge"; the "_negedge" kind with the clock inverted)
No timing and no X: every storage element starts at 0, as the RTL simulation
does with PQSE_SIM_INIT (the RAMs of the design become flip-flops in the sky130
netlist and have no reset). Power pins (pg_pin) are left out, as in a
synthesized netlist.

The models are traced (no verilator tracing_off): OpenSTA's read_vcd and
read_saif annotate activity on cell PINS (<instance>/<pin> under the scope),
not on net names, so the dump must hold every instance's ports.
"""
import re
import sys


# ---------------------------------------------------------------- Liberty reader
TOK = re.compile(r'''
    (?P<ws>\s+|\\\r?\n) |
    (?P<cmt>/\*.*?\*/|//[^\n]*) |
    (?P<str>"(?:[^"\\]|\\.|\\\r?\n)*") |
    (?P<punct>[(){}:;,]) |
    (?P<word>[^\s(){}:;,"]+)
''', re.S | re.X)


def tokens(text):
    for m in TOK.finditer(text):
        k = m.lastgroup
        if k in ('ws', 'cmt'):
            continue
        v = m.group(k)
        if k == 'str':
            v = v[1:-1].replace('\\\n', '').replace('\\\r\n', '')
        yield v


class Group:
    def __init__(self, kind, args):
        self.kind, self.args = kind, args
        self.attrs = {}
        self.groups = []

    def sub(self, kind):
        return [g for g in self.groups if g.kind == kind]


def parse(toks):
    """Parse statements until '}' (or the end); return the list of groups and
    the attributes."""
    root = Group('root', [])
    stack = [root]
    toks = list(toks)
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t == '}':
            stack.pop()
            i += 1
            continue
        if t == ';':
            i += 1
            continue
        name = t
        nxt = toks[i + 1] if i + 1 < n else None
        if nxt == ':':                                   # simple attribute
            j = i + 2
            val = []
            while j < n and toks[j] != ';' and toks[j] != '}':
                val.append(toks[j])
                j += 1
            stack[-1].attrs[name] = ' '.join(val)
            i = j + 1 if j < n and toks[j] == ';' else j
        elif nxt == '(':                                 # group or complex attribute
            j = i + 2
            args = []
            while j < n and toks[j] != ')':
                if toks[j] != ',':
                    args.append(toks[j])
                j += 1
            j += 1                                       # past ')'
            if j < n and toks[j] == '{':
                g = Group(name, args)
                stack[-1].groups.append(g)
                stack.append(g)
                j += 1
            else:
                stack[-1].attrs.setdefault(name, args)
                if j < n and toks[j] == ';':
                    j += 1
            i = j
        else:
            i += 1
    return root


# ---------------------------------------------------------------- Boolean functions
FTOK = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_\[\]]*|[01]|[!'&|^+*()])")


def fexpr(s):
    """Liberty function -> Verilog expression (! ' & | ^ + *, AND by adjacency)."""
    toks = FTOK.findall(s)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        t = toks[pos[0]]
        pos[0] += 1
        return t

    def primary():
        t = take()
        if t == '(':
            e = orx()
            take()                                       # ')'
            r = '(' + e + ')'
        elif t == '!':
            r = '~(' + primary() + ')'
        elif t == '0':
            r = "1'b0"
        elif t == '1':
            r = "1'b1"
        else:
            r = t
        while peek() == "'":
            take()
            r = '~(' + r + ')'
        return r

    def xorx():
        e = primary()
        while peek() == '^':
            take()
            e = '(' + e + ' ^ ' + primary() + ')'
        return e

    def andx():
        e = xorx()
        while True:
            t = peek()
            if t in ('&', '*'):
                take()
                e = '(' + e + ' & ' + xorx() + ')'
            elif t is not None and t not in ('|', '+', ')', '^', "'"):
                e = '(' + e + ' & ' + xorx() + ')'      # adjacency
            else:
                return e

    def orx():
        e = andx()
        while peek() in ('|', '+'):
            take()
            e = '(' + e + ' | ' + andx() + ')'
        return e

    r = orx()
    if pos[0] != len(toks):
        raise ValueError('cannot parse function "%s"' % s)
    return r


def edge(s):
    """'CLK' -> ('posedge CLK', 'CLK'), '!RESET_B' -> ('negedge RESET_B', '~RESET_B')."""
    s = s.strip()
    m = re.fullmatch(r'\(?\s*!\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)?', s)
    if m:
        return 'negedge ' + m.group(1), '~' + m.group(1)
    m = re.fullmatch(r"\(?\s*([A-Za-z_][A-Za-z0-9_]*)\s*'\s*\)?", s)
    if m:
        return 'negedge ' + m.group(1), '~' + m.group(1)
    m = re.fullmatch(r'\(?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)?', s)
    if m:
        return 'posedge ' + m.group(1), m.group(1)
    raise ValueError('cannot use "%s" as an edge' % s)


# ---------------------------------------------------------------- model writer
def icg_model(cell, ins, outs):
    """Integrated clock gate from its clock_gate_* pin attributes."""
    name = cell.args[0]
    kind = cell.attrs['clock_gating_integrated_cell'].strip().lower()
    clk = gclk = None
    ens = []
    for p in cell.sub('pin'):
        for pn in p.args:
            if p.attrs.get('clock_gate_clock_pin', '').lower() == 'true':
                clk = pn
            elif p.attrs.get('clock_gate_out_pin', '').lower() == 'true':
                gclk = pn
            elif p.attrs.get('clock_gate_enable_pin', '').lower() == 'true' or \
                    p.attrs.get('clock_gate_test_pin', '').lower() == 'true':
                ens.append(pn)
    if not (clk and gclk and ens):
        raise ValueError('%s: clock-gating pins not found' % name)
    neg = 'negedge' in kind
    lines = ['module %s (' % name]
    lines.append(',\n'.join(['  input  wire %s' % p for p in ins] +
                            ['  output wire %s' % p for p, _ in outs]))
    lines.append(');')
    lines.append("  reg en_l = 1'b0;")
    # latch transparent while the clock is in its inactive phase
    lines.append('  always @* if (%s%s) en_l = %s;' % ('' if neg else '!', clk, ' | '.join(ens)))
    if neg:
        lines.append('  assign %s = ~(~%s & en_l);' % (gclk, clk))
    else:
        lines.append('  assign %s = %s & en_l;' % (gclk, clk))
    for pn, _ in outs:
        if pn != gclk:
            lines.append("  assign %s = 1'b0;" % pn)
    lines.append('endmodule\n')
    return '\n'.join(lines)


def model(cell):
    name = cell.args[0]
    ins, outs = [], []
    for p in cell.sub('pin'):
        d = p.attrs.get('direction', '')
        for pn in p.args:
            if d == 'input':
                ins.append(pn)
            elif d == 'output':
                outs.append((pn, p))
    for b in cell.sub('bus') + cell.sub('bundle'):
        raise ValueError('%s: buses are not supported' % name)
    if 'clock_gating_integrated_cell' in cell.attrs:
        return icg_model(cell, ins, outs)
    if cell.sub('statetable'):
        raise ValueError('%s: statetable cells are not supported' % name)
    lines = ['module %s (' % name]
    ports = ['  input  wire %s' % p for p in ins] + ['  output wire %s' % p for p, _ in outs]
    lines.append(',\n'.join(ports))
    lines.append(');')
    for kind in ('ff', 'latch'):
        for g in cell.sub(kind):
            iq, iqn = g.args[0], (g.args[1] if len(g.args) > 1 else None)
            lines.append('  reg %s = 1\'b0;' % iq)
            if iqn:
                lines.append('  wire %s = ~%s;' % (iqn, iq))
            clr = g.attrs.get('clear')
            pre = g.attrs.get('preset')
            if kind == 'ff':
                ev = [edge(g.attrs['clocked_on'])[0]]
                cond = []
                if clr:
                    e, c = edge(clr)
                    ev.append(e)
                    cond.append((c, "1'b0"))
                if pre:
                    e, c = edge(pre)
                    ev.append(e)
                    cond.append((c, "1'b1"))
                lines.append('  always @(%s)' % ' or '.join(ev))
                body = []
                for k, (c, v) in enumerate(cond):
                    body.append('%sif (%s) %s <= %s;' % ('else ' if k else '', c, iq, v))
                nxt = '%s <= %s;' % (iq, fexpr(g.attrs['next_state']))
                body.append(('else ' if cond else '') + nxt)
                lines += ['    ' + b for b in body]
            else:
                en = fexpr(g.attrs['enable'])
                d = fexpr(g.attrs['data_in'])
                lines.append('  always @*')
                body = []
                if clr:
                    body.append("if (%s) %s = 1'b0;" % (fexpr(clr), iq))
                if pre:
                    body.append("%sif (%s) %s = 1'b1;" % ('else ' if body else '', fexpr(pre), iq))
                body.append('%sif (%s) %s = %s;' % ('else ' if body else '', en, iq, d))
                lines += ['    ' + b for b in body]
    for pn, p in outs:
        f = p.attrs.get('function') or p.attrs.get('state_function')
        if f is None:
            raise ValueError('%s: output %s has no function' % (name, pn))
        e = fexpr(f)
        ts = p.attrs.get('three_state')
        if ts:
            e = "(%s) ? 1'bz : %s" % (fexpr(ts), e)
        lines.append('  assign %s = %s;' % (pn, e))
    lines.append('endmodule\n')
    return '\n'.join(lines)


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    lib, netlist, out = sys.argv[1:]
    used = set(re.findall(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s+[^\s(;]+\s*\(',
                          open(netlist).read(), re.M))
    root = parse(tokens(open(lib).read()))
    libs = root.sub('library')
    cells = {}
    for L in libs:
        for c in L.sub('cell'):
            cells[c.args[0]] = c
    need = sorted(u for u in used if u in cells)
    missing = sorted(u for u in used if u.startswith('sky130_') and u not in cells)
    if missing:
        sys.exit('cells not in %s: %s' % (lib, ' '.join(missing)))
    with open(out, 'w') as f:
        f.write('// generated by scripts/pqse_lib2v.py from %s - do not edit\n' % lib)
        f.write('// behavioural zero-delay models, every storage element starts at 0\n')
        f.write('// traced: OpenSTA annotates activity on the instances\' pins\n\n')
        for n in need:
            f.write(model(cells[n]))
            f.write('\n')
    print('pqse_lib2v: %d cell models -> %s' % (len(need), out))


if __name__ == '__main__':
    main()
