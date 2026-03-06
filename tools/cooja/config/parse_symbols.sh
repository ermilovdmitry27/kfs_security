#!/bin/sh
set -eu

lib="$1"

# Emit section boundaries in the format expected by Cooja's COMMAND_* regexes,
# then append nm output with symbol sizes.
python3 - "$lib" <<'PY'
import subprocess
import sys

lib = sys.argv[1]
out = subprocess.check_output(["objdump", "-h", lib], text=True)

for line in out.splitlines():
    parts = line.split()
    if len(parts) < 6:
        continue
    name = parts[1]
    if name not in (".data", ".bss"):
        continue
    size = int(parts[2], 16)
    vma = int(parts[3], 16)
    if name == ".data":
        print(f".data d {vma:x}")
        print(f"_edata A {vma + size:x}")
    else:
        print(f"__bss_start A {vma:x}")
        print(f"_end A {vma + size:x}")
PY

nm -aP -S "$lib"
