#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# check_env.sh - check the things Bambu's co-simulation needs, before the
# 3-minute run fails with the unhelpful "The simulation does not end
# correctly".  Run with "make check-env"; "make hls" runs it first.
#
# Exit status 1 if something is certainly broken, 0 otherwise (warnings are
# printed but do not stop the build).
# -----------------------------------------------------------------------------
here="$(cd "$(dirname "$0")/.." && pwd)"
fail=0

ok()   { printf '  [ok]   %s\n' "$1"; }
warn() { printf '  [WARN] %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; fail=1; }

echo "checking the Bambu / co-simulation environment:"

# 1. The project path. Bambu's generated scripts do not quote paths, so a
#    space anywhere in the path breaks them.
case "$here" in
  *" "*) bad "project path contains a space: '$here'
         move the project to a path without spaces, e.g. ~/mlkem_hls" ;;
  *) ok "project path has no spaces" ;;
esac

# 2. WSL: building on the Windows drive (/mnt/c/...). The co-simulation passes
#    data between two processes through a memory-mapped file in the build
#    folder, which may not work on the Windows file system, and everything
#    there is several times slower.
case "$here" in
  /mnt/[a-zA-Z]/*) warn "the project is on a Windows drive ($here).
         The co-simulation may fail there, and builds are much slower.
         Copy it into the Linux file system and build there:
           cp -r \"$here\" ~/mlkem_hls && cd ~/mlkem_hls && make hls
         (Quartus on Windows can still reach it as \\\\wsl\$\\<distro>\\home\\<user>\\mlkem_hls)" ;;
  *) ok "project is on a Linux file system" ;;
esac

# 3. 32-bit C headers. Bambu compiles the testbench side of the co-simulation
#    with -m32; that needs libc6-dev-i386 and the /usr/include/asm link that
#    gcc-multilib provides (installing an ARM cross compiler removes it).
if ! command -v gcc > /dev/null; then
  bad "gcc not found: sudo apt install build-essential"
elif printf '#include <errno.h>\n#include <stdio.h>\nint main(void){return 0;}\n' \
     | gcc -m32 -x c -fsyntax-only - 2> /tmp/check_env_m32.$$; then
  ok "32-bit C headers (gcc -m32) work"
else
  if grep -q "asm/errno.h" /tmp/check_env_m32.$$; then
    bad "32-bit headers: asm/errno.h missing (gcc-multilib is not installed or was
         removed by installing gcc-arm-linux-gnueabihf). Fix, either:
           sudo apt install gcc-multilib
         or, if you need the ARM cross compiler as well:
           sudo ln -s x86_64-linux-gnu/asm /usr/include/asm"
  else
    bad "32-bit C headers do not work: sudo apt install gcc-multilib
$(sed 's/^/         /' /tmp/check_env_m32.$$ | head -5)"
  fi
fi
rm -f /tmp/check_env_m32.$$

# 4. C++ compiler for the Verilator side of the co-simulation
if command -v g++ > /dev/null; then ok "g++ found"; else bad "g++ not found: sudo apt install build-essential"; fi

# 5. Verilator on PATH (the co-simulation script calls it by name), and its
#    svdpi.h. Bambu looks for that header next to the verilator command; the
#    Makefile also passes Verilator's real include folder through CPATH, so
#    only a header that cannot be found at all is an error.
if command -v verilator > /dev/null; then
  ok "$(verilator --version | head -1)"
  vroot="$(verilator --getenv VERILATOR_ROOT 2> /dev/null)"
  bambu_guess="$(dirname "$(command -v verilator)")/../share/verilator/include/vltstd/svdpi.h"
  if [ -f "$bambu_guess" ]; then
    ok "Verilator's svdpi.h is where Bambu looks for it"
  elif [ -n "$vroot" ] && [ -f "$vroot/include/vltstd/svdpi.h" ]; then
    ok "Verilator's svdpi.h found in $vroot/include/vltstd (the Makefile passes it to Bambu)"
  else
    bad "Verilator's svdpi.h not found (VERILATOR_ROOT = '${vroot}'): the installation is
         incomplete. Reinstall Verilator (sudo apt install verilator, or 'sudo make install'
         in its source folder)"
  fi
else
  bad "verilator not found: sudo apt install verilator"
fi

# 6. Bambu itself
if command -v "${BAMBU:-bambu}" > /dev/null; then
  ok "bambu found: $(command -v "${BAMBU:-bambu}")"
else
  bad "bambu not found on PATH (see the guide, section 3.1)"
fi

# 7. Memory. Compiling the Verilated design needs a few GB; WSL gets half of
#    the PC's RAM by default.
avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo 2> /dev/null)
if [ -n "$avail_mb" ]; then
  if [ "$avail_mb" -lt 3000 ]; then
    warn "only ${avail_mb} MB of memory available; the C++ compile of the simulation may be
         killed. Close other programs, or give WSL more memory in %UserProfile%\\.wslconfig:
           [wsl2]
           memory=6GB
         then run 'wsl --shutdown' in Windows and reopen the terminal."
  else
    ok "${avail_mb} MB of memory available"
  fi
fi

if [ $fail -ne 0 ]; then
  echo "fix the [FAIL] items above, then run 'make hls' again"
  exit 1
fi
exit 0
