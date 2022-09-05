#!/bin/bash

### CREDITS: https://stackoverflow.com/questions/39913847/is-there-a-way-to-compile-a-python-application-into-static-binary/40057634#40057634

PYTHONLIBVER=python$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')$(python3-config --abiflags)

if ! command -v cython &> /dev/null; then
    echo "[E] cython command not found, see README.md file!"
    exit 1
fi

if ! command -v gcc &> /dev/null; then
    echo "[E] gcc command not found, please install it!"
    exit 1
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "[I] convert Python source to C source."
cython "$SCRIPT_DIR/eren.py" --embed

echo "[I] compile the C source."
gcc -Os $(python3-config --includes) "$SCRIPT_DIR/eren.c" -o eren.bin $(python3-config --ldflags) -l$PYTHONLIBVER

echo "[I] adding cap_net_raw to the binary (needed for UDP port scan)."
sudo setcap cap_net_raw+ep eren.bin

echo "[I] cleanup."
rm eren.c