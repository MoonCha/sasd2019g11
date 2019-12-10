#!/bin/bash

set -e

READTWELF=${READTWELF:-"tests/readtwelf"}
INPUT_DIR=${INPUT_DIR:-"afl_input"}
OUTPUT_DIR=${OUTPUT_DIR:-"afl_output"}

if ! [[ -f "$READTWELF" && -x "$READTWELF" ]]; then
    echo "$READTWELF not found or not executable. Please run this script from the build folder with \`make afl\`" 1>&2
    exit 1
fi

if ! [[ -d "$INPUT_DIR" ]]; then
    echo "Please create the directory \"$INPUT_DIR\" or point INPUT_DIR to a folder containing ONLY test binaries." 1>&2
    exit 1
fi

TMPFILE=$(mktemp)

AFL_SKIP_CPUFREQ=1 afl-fuzz -i "$INPUT_DIR" -o "$OUTPUT_DIR" -f "$TMPFILE" -- "$READTWELF" "$TMPFILE"
