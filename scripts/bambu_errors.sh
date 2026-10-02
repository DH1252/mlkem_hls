#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# bambu_errors.sh - pull the real cause out of a failed Bambu run.
#
# Bambu only says "The simulation does not end correctly" when the
# co-simulation fails; the compiler or simulator message that explains why is
# buried in the verbose log. Usage: bambu_errors.sh build/hls/bambu.log
# -----------------------------------------------------------------------------
log="$1"
[ -f "$log" ] || { echo "no log file $log"; exit 1; }

pattern='fatal error|error: |Error [0-9]+|Killed|No such file|[Cc]annot (open|find|allocate|create)|undefined reference|Segmentation fault|Bus error|[Oo]ut of memory|memory exhausted|bad_alloc|Wrong system application|Operation not supported|Invalid argument|Permission denied|mmap'

echo
echo "================ Bambu failed: messages from $log ================"
if grep -qE "$pattern" "$log"; then
  grep -nE "$pattern" "$log" | awk '!seen[substr($0, index($0, ":") + 1)]++' | tail -25
else
  echo "(no compiler or simulator error found; last lines of the log:)"
fi
echo "----------------------------- log tail -----------------------------"
tail -12 "$log"
echo "--------------------------------------------------------------------"

hint() { echo "LIKELY CAUSE: $1"; }
if grep -q "asm/errno.h" "$log"; then
  hint "32-bit headers missing. sudo apt install gcc-multilib
              (or, if you also need the ARM cross compiler: sudo ln -s x86_64-linux-gnu/asm /usr/include/asm)"
elif grep -qE "bits/libc-header-start.h|gnu/stubs-32.h" "$log"; then
  hint "32-bit C library headers missing. sudo apt install gcc-multilib"
elif grep -q "svdpi.h" "$log"; then
  hint "Bambu cannot find Verilator's svdpi.h (verilator on your PATH is a symlink or
              wrapper outside Verilator's install folder). Use this project's Makefile, which
              passes the right folder, or: export CPATH=\$(verilator --getenv VERILATOR_ROOT)/include/vltstd"
elif grep -qE "Killed|[Oo]ut of memory|memory exhausted|bad_alloc|Cannot allocate" "$log"; then
  hint "not enough memory for the simulation compile. Close other programs or raise
              WSL's memory limit (%UserProfile%\\.wslconfig: [wsl2] memory=6GB, then 'wsl --shutdown')."
elif grep -q "libtinfo" "$log"; then
  hint "Clang front end selected; use --compiler=I386_GCC8 (the Makefile does)."
elif grep -qE "verilator: (command )?not found" "$log"; then
  hint "Verilator not installed: sudo apt install verilator"
else
  case "$(pwd)" in
    *" "*) hint "the path contains a space; move the project to e.g. ~/mlkem_hls" ;;
    /mnt/[a-zA-Z]/*) hint "the project is on a Windows drive (/mnt/...); copy it to the Linux
              file system (cp -r . ~/mlkem_hls) and run make hls there" ;;
    *) echo "Run 'make check-env'; if it finds nothing, send the lines above." ;;
  esac
fi
exit 1
