#!/usr/bin/env python3
"""pqse_qspice_test.py - can QSPICE (Windows) run OpenRAM's sky130 SRAM decks,
and is it faster than ngspice? A feasibility test, not part of the flow.

    make se-sram-qspice-test [QS_SHAPE=a6_d65] [QSPICE="/mnt/c/Program Files/QSPICE/QSPICE64.exe"]
    python3 scripts/power/openram/pqse_qspice_test.py --tmp <OpenRAM temp dir> \\
        [--out /mnt/c/pqse_qspice_test] [--deck delay_stim.sp] [--qspice <exe>] [--ngspice]

Input: the temp directory of an OpenRAM characterization (tmp_<shape>; make
se-sram-char OR_KEEP=1 keeps it after the run). Its stimulus (delay_stim.sp:
the trimmed SRAM netlist, sources, .meas statements, .TRAN) includes the netlist
and the measurement file from the temp directory and the sky130 models from
the PDK.

What it does:
  1. copies the stimulus and every file it includes from the temp directory
     into --out (on the Windows side, default /mnt/c/pqse_qspice_test);
  2. writes <deck>_qspice.cir: include paths as Windows paths (copies:
     C:\\...; the sky130 models stay in WSL and are referenced as
     \\\\wsl.localhost\\<distro>\\..., or --models-win names a copy on C:),
     ngspice-only .OPTIONS tokens (KLU, ACCT, PROBE, POST) removed, and the
     netlist copies with their transistors as M devices (<name>_qspice.sp):
     OpenRAM instantiates the sky130 FETs with X (subcircuit syntax), but this
     PDK defines them as .model cards; ngspice turns such an X line into a
     MOSFET, QSPICE stops with "No such subcircuit: SKY130_FD_PR__..._FET...";
  3. writes <deck>_ngspice.sp: the same deck with Linux paths;
  4. with --qspice <exe> runs QSPICE on <deck>_qspice.cir from WSL, timed, and
     shows the end of its output and the files it wrote. QSPICE's command
     line is not documented here: if it needs other options, give them with
     --qspice-args, or open the .cir in QSPICE's GUI (QUX) instead;
  5. with --ngspice runs <deck>_ngspice.sp in ngspice afterwards (threads from
     --threads via a .spiceinit), timed, as the baseline.

Result (QSPICE, sky130 from open_pdks via OpenRAM's ciel): with the X -> M
rewrite QSPICE runs, but finds none of the sky130 models ("Didn't find a
model for SKY130_FD_PR__SPECIAL_NFET_LATCH... -- defaults assumed") and
simulates level-1 default MOSFETs: not usable without converting the model
library. The script reports this as its verdict.

What to look for: whether QSPICE gets through the sky130 model library (the
models are written for ngspice: .option scale, nested .lib sections, binned
BSIM4 models in subcircuits), whether the transient finishes, whether the
.meas results agree with ngspice's, and the two run times.
"""
import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import time

INC = re.compile(r'^(\s*)\.(include|inc|lib)\s+(.*)$', re.IGNORECASE)
NG_ONLY = ("KLU", "ACCT", "PROBE", "POST=1")
FET = re.compile(r"^sky130_fd_pr__\S*fet\S*$", re.IGNORECASE)


def x_to_m(text):
    """X instances of sky130 FET models -> M devices; returns (text, count)"""
    out, n = [], 0
    for ln in text.splitlines():
        if ln[:1] in "xX" and any(FET.match(t) for t in ln.split()[1:]):
            ln = "M" + ln[1:]
            n += 1
        out.append(ln)
    return "\n".join(out) + "\n", n


def parse_inc(ln):
    """'.include <path> ...' -> (indent, keyword, path, rest) or None. OpenRAM writes
    '.include <path>' without a newline, so the next card can follow the path
    directly (".../delay_meas.sp.TEMP 25"): an unquoted path that does not exist
    is cut at the longest prefix that does."""
    m = INC.match(ln)
    if not m:
        return None
    ind, kw, rest = m.groups()
    rest = rest.strip()
    if rest.startswith('"'):
        end = rest.find('"', 1)
        if end < 0:
            return None
        return ind, kw, rest[1:end], rest[end + 1:]
    tok = rest.split()[0] if rest else ""
    after = rest[len(tok):]
    if "/" not in tok:
        return None                                   # a section name, not a file
    if not os.path.isfile(tok):
        cuts = [i for i, c in enumerate(tok) if c == "." and os.path.isfile(tok[:i])]
        if cuts:
            i = cuts[-1]
            return ind, kw, tok[:i], tok[i:] + after
    return ind, kw, tok, after


def winpath(p):
    """Linux path -> Windows path (wslpath -w); unchanged outside WSL"""
    try:
        r = subprocess.run(["wslpath", "-w", p], capture_output=True, text=True, check=True)
        return r.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return p


def default_tmp(shape):
    for d in (os.path.expanduser("~/.cache/pqse_openram"), "build/sepower/openram"):
        p = os.path.join(d, "tmp_" + shape)
        if os.path.isdir(p):
            return p
    return os.path.join(os.path.expanduser("~/.cache/pqse_openram"), "tmp_" + shape)


def copy_tree(path, tmp, out, done):
    """copy a file from the temp directory into out, then the temp files it includes"""
    name = os.path.basename(path)
    if name in done:
        return
    done.add(name)
    shutil.copy(path, os.path.join(out, name))
    for ln in open(path, errors="replace"):
        m = parse_inc(ln)
        if m:
            inc = m[2]
            if os.path.dirname(os.path.abspath(inc)) == os.path.abspath(tmp) and os.path.isfile(inc):
                copy_tree(inc, tmp, out, done)


def rewrite(path, tmp, out, windows, models_win=None):
    """the deck with include paths pointing at the copies (or the models in place);
    windows: the QSPICE deck (Windows paths, the _qspice netlist copies)"""
    lines = []
    for ln in open(path, errors="replace").read().splitlines():
        m = parse_inc(ln)
        if m:
            ind, kw, inc, rest = m
            if os.path.dirname(os.path.abspath(inc)) == os.path.abspath(tmp):
                inc = os.path.join(os.path.abspath(out), os.path.basename(inc))
                if windows:
                    base, ext = os.path.splitext(inc)
                    if os.path.isfile(base + "_qspice" + ext):
                        inc = base + "_qspice" + ext
            elif windows and models_win and kw.lower() == "lib":
                inc = models_win
            p = (inc if inc == models_win else winpath(inc)) if windows else inc
            tail = rest
            extra = ""
            if rest.lstrip().startswith("."):          # OpenRAM writes ".include x" without a newline
                tail, extra = "", rest.lstrip()
            lines.append('%s.%s "%s"%s' % (ind, kw, p, tail))
            if extra:
                lines.append(extra)
            continue
        if windows and ln.upper().startswith(".OPTIONS"):
            toks = [t for t in ln.split() if t.upper() not in NG_ONLY]
            ln = " ".join(toks) if len(toks) > 1 else "* " + ln
        lines.append(ln)
    return "\n".join(lines) + "\n"


def run(cmd, cwd, log):
    t0 = time.time()
    with open(log, "w") as f:
        r = subprocess.run(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT)
    return r.returncode, time.time() - t0


def tail(path, n=20):
    try:
        lines = open(path, errors="replace").read().splitlines()
    except OSError:
        return "(no %s)" % path
    return "\n".join("    " + x for x in lines[-n:])


def meas_lines(path):
    out = []
    for ln in open(path, errors="replace"):
        m = re.match(r'\s*([a-z_][\w.]*)\s*=\s*(-?[\d.]+(?:e[-+]?\d+)?)', ln, re.IGNORECASE)
        if m and ("delay" in m.group(1).lower() or "power" in m.group(1).lower()
                  or "slew" in m.group(1).lower()):
            out.append("%-28s %s" % (m.group(1), m.group(2)))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--shape", default="a6_d65")
    ap.add_argument("--tmp", help="OpenRAM temp directory (default: tmp_<shape> in OR_TMP)")
    ap.add_argument("--out", default="/mnt/c/pqse_qspice_test")
    ap.add_argument("--deck", default="delay_stim.sp")
    ap.add_argument("--ngspice", action="store_true", help="run the ngspice baseline")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--qspice", help="QSPICE simulator executable, e.g. "
                    "'/mnt/c/Program Files/QSPICE/QSPICE64.exe'")
    ap.add_argument("--qspice-args", default="", help="extra QSPICE arguments before the netlist")
    ap.add_argument("--models-win", help="Windows path of sky130.lib.spice for the QSPICE deck "
                    "(a copy on C:, e.g. C:\\sky130A\\libs.tech\\ngspice\\sky130.lib.spice)")
    a = ap.parse_args()

    tmp = os.path.abspath(a.tmp or default_tmp(a.shape))
    deck = os.path.join(tmp, a.deck)
    if not os.path.isfile(deck):
        sys.exit("pqse_qspice_test: %s not found. Run the shape with the temp files kept:\n"
                 "  make se-sram-char OPENRAM_DIR=... SRAM_SHAPES=%s OR_KEEP=1\n"
                 "(or copy the temp directory while it runs)" % (deck, a.shape))
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)

    done = set()
    copy_tree(deck, tmp, out, done)
    stem = os.path.splitext(a.deck)[0]
    for name in sorted(done):
        if name == os.path.basename(deck):
            continue
        text, n = x_to_m(open(os.path.join(out, name), errors="replace").read())
        if n:
            b, e = os.path.splitext(name)
            open(os.path.join(out, b + "_qspice" + e), "w").write(text)
            print("%s: %d sky130 FET instances X -> M in %s_qspice%s" % (name, n, b, e))
    qs = os.path.join(out, stem + "_qspice.cir")
    ng = os.path.join(out, stem + "_ngspice.sp")
    open(qs, "w").write(rewrite(deck, tmp, out, windows=True, models_win=a.models_win))
    open(ng, "w").write(rewrite(deck, tmp, out, windows=False))
    print("copied from %s: %s" % (tmp, ", ".join(sorted(done))))
    print("QSPICE deck:  %s  (%s)" % (qs, winpath(qs)))
    print("ngspice deck: %s" % ng)
    print("includes in the QSPICE deck:")
    for ln in open(qs):
        if parse_inc(ln):
            print("    " + ln.rstrip())

    if a.qspice:
        t_start = time.time()
        cmd = [a.qspice] + a.qspice_args.split() + [winpath(qs)]
        print("\nrunning QSPICE: %s\n  (output: %s)" % (" ".join(cmd), os.path.join(out, "qspice.out")),
              flush=True)
        rc, dt = run(cmd, out, os.path.join(out, "qspice.out"))
        print("QSPICE: exit %d, %.1f s; output:" % (rc, dt))
        print(tail(os.path.join(out, "qspice.out"), 30))
        try:
            qtext = open(os.path.join(out, "qspice.out"), errors="replace").read()
        except OSError:
            qtext = ""
        if "Didn't find a model" in qtext:
            print("VERDICT: QSPICE did not load the sky130 models and fell back to level-1 default\n"
                  "MOSFETs: its results mean nothing for sky130 (this PDK's models are binned\n"
                  ".model cards, <name>.0 .. <name>.N, selected by W / L).")
        new = [p for p in glob.glob(os.path.join(out, "*")) if os.path.getmtime(p) >= t_start - 1
               and not p.endswith("qspice.out")]
        print("files QSPICE wrote: %s" % (", ".join(os.path.basename(p) for p in new) or "none"))
        for p in new:
            if p.lower().endswith((".log", ".lis", ".txt", ".meas")):
                m = meas_lines(p)
                print("  %s:\n%s" % (os.path.basename(p),
                                     "\n".join("    " + x for x in m[:30]) if m else tail(p)))
        if dt < 2 and not new:
            print("QSPICE returned at once and wrote nothing: it probably did not take the netlist\n"
                  "from the command line. Open %s in QSPICE's GUI instead, or find its\n"
                  "command-line options (QSPICE help) and pass them with --qspice-args." % winpath(qs))

    if a.ngspice:
        with open(os.path.join(out, ".spiceinit"), "w") as f:
            f.write("set num_threads=%d\n" % a.threads)
        log = os.path.join(out, "ngspice.lis")
        print("\nrunning the ngspice baseline (%d threads; can take minutes)\n  (log: %s)"
              % (a.threads, log), flush=True)
        rc, dt = run(["ngspice", "-b", "-o", log, ng], out, os.path.join(out, "ngspice.out"))
        print("ngspice: exit %d, %.1f s" % (rc, dt))
        m = meas_lines(log)
        print("\n".join("    " + x for x in m[:30]) if m else tail(log))

    if not a.qspice and not a.ngspice:
        print("\nnext: --qspice <QSPICE64.exe> to run QSPICE from WSL, --ngspice for the baseline,\n"
              "or open %s in QSPICE's GUI" % winpath(qs))

if __name__ == "__main__":
    main()
