#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
CLI=${ARDUINO_CLI:-arduino-cli}
command -v "$CLI" >/dev/null 2>&1 || CLI=/root/esp32-portable/tools/arduino-cli
python3 "$ROOT/tools/generate_ui.py"
python3 "$ROOT/tests/validate.py"
mkdir -p "$ROOT/build"
"$CLI" compile --fqbn esp32:esp32:esp32cam --build-property build.partitions=min_spiffs --output-dir "$ROOT/build" "$ROOT/firmware/Wav32"
printf '\nWav32 compilado. No se ha flasheado.\n%s\n' "$ROOT/build/Wav32.ino.bin"
