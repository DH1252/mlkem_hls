#!/usr/bin/env python3
"""pqse_openram_run.py - OpenRAM's sram_compiler.py for one PQSE SRAM shape,
with the SPICE characterization cut down to what the energy flow needs.

    pqse_openram_run.py [sram_compiler options] <config.py>

make se-sram-char runs it in place of $OPENRAM_DIR/sram_compiler.py (same
steps, same options, same outputs) and sets the environment below. OpenRAM's
characterizer (compiler/characterizer/delay.py, analyze) runs about 20 ngspice
transients per shape; most of them go into things the energy flow does not use:

  1. the minimum-period binary search (to 5 %, per read port). Skipped
     (PQSE_OR_MINPERIOD=0, default): the shape is characterized at a fixed
     period, PQSE_OR_PERIOD ns (default 10, OpenRAM's own first try; doubled
     if the SRAM fails at it), which the .lib then gives as its minimum_period.
     pqse_sram_char.py takes energy = average power over one cycle x that
     period, so the energy per access is that of one cycle at this period: the
     dynamic part hardly depends on it, the leakage share of a cycle does.
  2. one leakage transient of the UNTRIMMED netlist (1024 x 25: ~150 k
     transistors; the run that took gigabytes). Skipped (PQSE_OR_FULL_LEAK=0,
     default): the leakage is that of the trimmed netlist, a lower bound
     (estimate for the whole array at 25 C: well under 1 uJ per KeyGen).

and the ngspice runs themselves are made faster:

  3. step ceiling. OpenRAM writes .TRAN 10p <stop> 0n 10p: at most 10 ps per
     step even where nothing switches. PQSE_OR_TMAX_PS (default 50) raises the
     ceiling; the time-step control still refines every edge. 10 restores
     OpenRAM's value (try it if a shape fails its delay checks).
  4. KLU sparse solver (PQSE_OR_KLU=1, default): adds KLU to OpenRAM's
     .OPTIONS line. Needs an ngspice built with KLU (ngspice -v; a build
     without it warns and uses its default solver).
  5. working directory. OpenRAM writes ngspice's .spiceinit (threads,
     ngbehavior=hsa) into its temp directory, but starts ngspice in the
     current directory, where ngspice looks for it, so it was never read.
     The run goes to PQSE_OR_RUNDIR, with a .spiceinit there: num_threads =
     PQSE_OR_THREADS and (PQSE_OR_NGFAST=1, default) the two settings the
     sky130 / ngspice guides give for faster model loading, ng_nomodcheck
     (no model-parameter checks) and skywaterpdk (skips checks while
     reading the PDK's .lib), and (PQSE_OR_HSA=1, default) ngbehavior=hsa,
     the third setting of those guides (HSPICE-compatible reading of the PDK
     libraries, the largest part of their speed-up). With hsa, ngspice no
     longer turns an X instance of a .model card into a MOSFET, and OpenRAM
     instantiates every sky130 transistor with X; some of them (the SRAM
     cell devices, e.g. sky130_fd_pr__special_nfet_01v8 / _latch) are .model
     cards in this PDK, others are .subckt wrappers. So every netlist a
     stimulus includes is first copied to the temp directory with the X
     instances of sky130 FET models that are NOT a .subckt (in the PDK or the
     netlist) written as M devices, and the stimulus includes that copy. The
     PDK's .subckt names come from a scan of its libs.tech/ngspice and
     libs.ref/sky130_fd_pr. PQSE_OR_HSA=0 goes back to plain mode. With
     PQSE_OR_NIX=1 the run stays in the OpenRAM checkout instead (nix
     develop needs its flake.nix there).
  7. Xyce raw file. OpenRAM starts Xyce with -r timing.raw: every node at
     every time step written to disk, never read (OpenRAM takes Xyce's
     measurements from its stdout). Under WSL with the files on /mnt/<drive>
     that write is most of the run time and Xyce sits idle. Dropped
     (PQSE_OR_XYCE_RAW=1 keeps it). The step ceiling (3) applies to Xyce too;
     KLU (4) is OpenRAM's own setting for Xyce.
  6. fail fast. A simulation that fails is retried by OpenRAM at twice the
     period, up to 8 times; when ngspice itself stopped with an error (not a
     timing failure) the run ends at once with ngspice's message.

PQSE_OR_MINPERIOD=1 PQSE_OR_FULL_LEAK=1 PQSE_OR_TMAX_PS=10 PQSE_OR_KLU=0 give
OpenRAM's own characterization. The analytical model (analytical_delay = True)
runs unchanged.
"""
import datetime
import importlib
import os
import re
import subprocess
import sys


def env(name, default):
    return os.environ.get(name, default)


class _StimRewrite:
    """Proxy of an ngspice stimulus file while stimuli.write_control writes
    the control cards: raises the .TRAN step ceiling, adds KLU to .OPTIONS."""

    def __init__(self, f, tmax_ps, klu):
        self._f, self._tmax_ps, self._klu = f, tmax_ps, klu

    def write(self, s):
        if self._tmax_ps and s.startswith(".TRAN "):
            p = s.split()                    # .TRAN <tstep> <tstop> 0n <tmax> UIC
            if len(p) >= 5:
                p[4] = "%gp" % self._tmax_ps
                s = " ".join(p) + "\n"
        elif self._klu and s.startswith(".OPTIONS ") and "method=gear" in s:
            s = s.rstrip("\n") + " KLU\n"
        return self._f.write(s)

    def __getattr__(self, name):
        return getattr(self._f, name)


def run_dir(root):
    """ngspice reads .spiceinit from its working directory"""
    if env("PQSE_OR_NIX", "0") == "1":
        os.chdir(root)
        return "OpenRAM checkout (Nix)"
    d = env("PQSE_OR_RUNDIR", "")
    if not d:
        return "unchanged"
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, ".spiceinit"), "w") as f:
        f.write("* written by scripts/power/openram/pqse_openram_run.py\n")
        f.write("set num_threads=%d\n" % int(env("PQSE_OR_THREADS", "4")))
        if env("PQSE_OR_NGFAST", "1") == "1":
            f.write("set ng_nomodcheck\n")     # no model-parameter checks
            f.write("set skywaterpdk\n")       # skip checks while reading the PDK libs
        if env("PQSE_OR_HSA", "1") == "1":
            f.write("set ngbehavior=hsa\n")   # needs the X -> M netlist copies (patch)
    os.chdir(d)
    return d


FATAL = ("Simulation interrupted due to error", "unknown subckt", "Could not find",
         "Timestep too small", "Error on line", "fatal")


def spice_errors(temp):
    """ngspice's fatal messages from the last run (spice_stdout.log, timing.lis)"""
    out = []
    for name in ("spice_stdout.log", "spice_stderr.log", "timing.lis"):
        try:
            lines = open(os.path.join(temp, name), errors="replace").read().splitlines()
        except OSError:
            continue
        for ln in lines:
            if any(k in ln for k in FATAL) and ln.strip()[:300] not in out:
                out.append(ln.strip()[:300])
    return "\n".join(out[:10])


FETNAME = re.compile(r"^sky130_fd_pr__\S*fet\S*$", re.IGNORECASE)


def pdk_subckts(lib):
    """lower-case names of the sky130_fd_pr .subckt definitions in the PDK that
    holds lib (<pdk>/libs.tech/ngspice/sky130.lib.spice)"""
    ngdir = os.path.dirname(os.path.abspath(lib))
    root = os.path.dirname(os.path.dirname(ngdir))
    dirs = [d for d in (ngdir, os.path.join(root, "libs.ref", "sky130_fd_pr")) if os.path.isdir(d)]
    pat = r"^[[:space:]]*\.subckt[[:space:]]+sky130_fd_pr__[^[:space:]]+"
    names = set()
    try:
        r = subprocess.run(["grep", "-rhoiE", pat] + dirs, capture_output=True, text=True)
        text = r.stdout
    except OSError:
        text = ""
        for d in dirs:
            for dp, _, fs in os.walk(d):
                for fn in fs:
                    try:
                        for ln in open(os.path.join(dp, fn), errors="replace"):
                            if ln.lstrip()[:7].lower() == ".subckt":
                                text += ln.strip() + "\n"
                    except OSError:
                        pass
    for ln in text.splitlines():
        p = ln.split()
        if len(p) > 1:
            names.add(p[1].lower())
    return names, dirs


def x_to_m(src, dst, subckts):
    """copy netlist src to dst with X instances of sky130 FET .model cards as M
    devices (the cell is the last token before the name=value parameters;
    continuation lines are followed); returns the number changed"""
    lines = open(src, errors="replace").read().splitlines()
    local = {ln.split()[1].lower() for ln in lines
             if ln.lstrip()[:7].lower() == ".subckt" and len(ln.split()) > 1}
    out, n, i = [], 0, 0
    while i < len(lines):
        j = i + 1
        while j < len(lines) and lines[j].startswith("+"):
            j += 1
        first = lines[i]
        if first[:1] in "xX":
            toks = " ".join([first] + [c[1:] for c in lines[i + 1:j]]).split()
            plain = [t for t in toks[1:] if "=" not in t]
            cell = plain[-1] if plain else ""
            if FETNAME.match(cell) and cell.lower() not in subckts and cell.lower() not in local:
                first = "M" + first[1:]
                n += 1
        out.append(first)
        out.extend(lines[i + 1:j])
        i = j
    with open(dst, "w") as f:
        f.write("\n".join(out) + "\n")
    return n


def patch(OPTS, debug):
    dmod = importlib.import_module("openram.characterizer.delay")
    smod = importlib.import_module("openram.characterizer.stimuli")
    delay, stimuli = dmod.delay, smod.stimuli
    notes = []

    if env("PQSE_OR_MINPERIOD", "0") != "1":
        period = float(env("PQSE_OR_PERIOD", "10"))
        # find_feasible_period starts here (and doubles it if a read fails)
        dmod.tech.spice["feasible_period"] = period

        def find_min_period(self, feasible_delays):
            self.targ_read_ports = []
            self.targ_write_ports = []
            debug.info(1, "PQSE: minimum-period search skipped, period {0}ns".format(self.period))
            return float(self.period)

        delay.find_min_period = find_min_period
        notes.append("fixed period %g ns (no minimum-period search)" % period)

    if env("PQSE_OR_FULL_LEAK", "0") != "1":
        def run_power_simulation(self):
            debug.info(1, "PQSE: leakage of the trimmed netlist only (full-array run skipped)")
            self.write_power_stimulus(trim=True)
            self.stim.run_sim(self.power_stim_sp)
            leak = dmod.parse_spice_list("timing", "leakage_power")
            debug.check(leak != "Failed", "Could not measure leakage power.")
            debug.info(1, "Leakage power of trimmed array is {0} mW".format(leak * 1e3))
            return (leak * 1e3, leak * 1e3)

        delay.run_power_simulation = run_power_simulation
        notes.append("leakage of the trimmed netlist (no full-array run)")

    # fail fast: ngspice errors are not timing failures, a longer period won't help
    run_delay_simulation = delay.run_delay_simulation

    def run_delay_simulation_checked(self):
        result = run_delay_simulation(self)
        if not result[0]:
            fatal = spice_errors(OPTS.openram_temp)
            if fatal:
                debug.error("ngspice stopped with an error at period {0}ns (not a timing "
                            "failure):\n{1}\n(logs in {2})".format(self.period, fatal,
                                                                 OPTS.openram_temp), 1)
        return result

    delay.run_delay_simulation = run_delay_simulation_checked

    xyce = OPTS.spice_name in ("Xyce", "xyce")
    if xyce and env("PQSE_OR_XYCE_RAW", "0") != "1":
        class _NoRaw:
            """subprocess for stimuli.run_sim: Xyce without -r <temp>timing.raw"""
            def run(self, cmd, *a, **k):
                if isinstance(cmd, str):
                    cmd = re.sub(r"\s-r\s+\S*timing\.raw", "", cmd)
                return subprocess.run(cmd, *a, **k)

            def __getattr__(self, name):
                return getattr(subprocess, name)

        smod.subprocess = _NoRaw()
        notes.append("Xyce without the raw file")

    if OPTS.spice_name == "ngspice" and env("PQSE_OR_HSA", "1") == "1":
        libs = [v[0][0] for v in dmod.tech.spice["fet_libraries"].values() if v]
        subckts, dirs = pdk_subckts(libs[0]) if libs else (set(), [])
        if not subckts:
            debug.warning("PQSE: no sky130_fd_pr .subckt found in {0}: every X instance of a "
                          "sky130 FET becomes an M device".format(dirs))
        write_include = stimuli.write_include
        converted = {}

        def write_include_m(self, circuit):
            if os.path.isfile(circuit):
                dst = os.path.join(OPTS.openram_temp, "pqse_m_" + os.path.basename(circuit))
                n = x_to_m(circuit, dst, subckts)
                if converted.get(circuit) != n:
                    converted[circuit] = n
                    debug.info(1, "PQSE: {0}: {1} sky130 FET instances X -> M".format(circuit, n))
                circuit = dst
            return write_include(self, circuit)

        stimuli.write_include = write_include_m
        notes.append("ngbehavior=hsa (netlists with sky130 FET models as M devices; "
                     "%d PDK subcircuits kept as X)" % len(subckts))

    tmax = float(env("PQSE_OR_TMAX_PS", "50"))
    # KLU: ngspice only (OpenRAM sets LINSOL type=klu for Xyce itself; its
    # TIMEINT line also contains method=gear and must not get KLU)
    klu = env("PQSE_OR_KLU", "1") == "1" and OPTS.spice_name == "ngspice"
    if (OPTS.spice_name == "ngspice" or xyce) and (tmax != 10 or klu):
        write_control = stimuli.write_control

        def write_control_fast(self, end_time, runlvl=4):
            real = self.sf
            self.sf = _StimRewrite(real, tmax if tmax != 10 else 0, klu)
            try:
                return write_control(self, end_time, runlvl)
            finally:
                self.sf = real

        stimuli.write_control = write_control_fast
        if tmax != 10:
            notes.append(".TRAN step ceiling %g ps" % tmax)
        if klu:
            notes.append("KLU solver")
    return notes


def main():
    home = env("OPENRAM_HOME", "")
    if not home:
        sys.exit("pqse_openram_run: OPENRAM_HOME is not set (make se-sram-char sets it)")
    root = os.path.dirname(os.path.abspath(home.rstrip("/")))
    sys.path.insert(0, root)
    from common import make_openram_package
    make_openram_package()
    import openram

    sys.argv = [os.path.join(root, "sram_compiler.py")] + sys.argv[1:]
    (OPTS, args) = openram.parse_args()
    if len(args) != 1:
        print(openram.USAGE)
        sys.exit(2)
    OPTS.top_process = 'openram'
    from openram import debug

    # the same steps as sram_compiler.py, with the patches before the SRAM is built
    openram.init_openram(config_file=os.path.abspath(args[0]))
    openram.setup_bitcell()
    openram.print_banner()
    start_time = datetime.datetime.now()
    openram.print_time("Start", start_time)
    openram.report_status()
    if not OPTS.analytical_delay:
        where = run_dir(root)
        notes = patch(OPTS, debug)
        debug.print_raw("PQSE: simulator working directory: {}".format(where))
        debug.print_raw("PQSE: {}".format("; ".join(notes) if notes else "OpenRAM's characterization"))
    debug.print_raw("Words per row: {}".format(OPTS.words_per_row))

    from openram import sram
    s = sram()
    s.save()

    openram.end_openram()
    openram.print_time("End", datetime.datetime.now(), start_time)


if __name__ == "__main__":
    main()
