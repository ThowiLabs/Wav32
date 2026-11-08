#!/bin/sh
# Instala Wav32 en una ESP32-CAM. Puede proteger una MAC concreta (PROTECTED_MAC) para no sobrescribirla.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
PORT=/dev/ttyUSB0
if [ "$#" -ge 1 ]; then PORT="$1"; fi
ESPTOOL=${ESPTOOL:-esptool}
PROTECTED_MAC=${PROTECTED_MAC:-}
APP="$ROOT/build/Wav32.ino.bin"
BOOT="$ROOT/build/Wav32.ino.bootloader.bin"
PART="$ROOT/build/Wav32.ino.partitions.bin"
for file in "$APP" "$BOOT" "$PART";do
    test -s "$file" || { echo "Falta $file. Ejecuta tools/build.sh" >&2; exit 1; }
done
echo "Comprobando identidad en $PORT: mantén GPIO0 conectado a GND y pulsa RESET."
INFO=$("$ESPTOOL" --chip esp32 --port "$PORT" --baud 115200 --before no-reset \
    --after no-reset read-mac 2>&1)
printf '%s\n' "$INFO" | grep -E 'Chip type|MAC:' | head -n 5
MAC=$(printf '%s\n' "$INFO" | sed -n 's/.*MAC: *\([[:xdigit:]:]\{17\}\).*/\1/p' | tail -n 1 | tr 'A-F' 'a-f')
[ -n "$MAC" ] || { echo "No se identificó la placa. Flasheo cancelado." >&2;exit 1; }
if [ -n "$PROTECTED_MAC" ] && [ "$MAC" = "$PROTECTED_MAC" ]; then
  echo "PROTECCIÓN: placa protegida ($MAC). No se ha grabado Wav32." >&2
  exit 1
fi
echo "Placa distinta confirmada: $MAC"
mkdir -p "$ROOT/backups"
SAFE=$(printf '%s' "$MAC" | tr ':' '-')
BACKUP="$ROOT/backups/second-$SAFE-antes-Wav32.bin"
if [ ! -f "$BACKUP" ]; then
    echo "Guardando respaldo antes del primer flasheo: $BACKUP"
    "$ESPTOOL" --chip esp32 --port "$PORT" --baud 115200 --before no-reset \
      --after no-reset read-flash 0x0 0x400000 "$BACKUP"
fi
[ "$(wc -c < "$BACKUP")" -eq 4194304 ] || {
    echo "Respaldo incompleto. No se ha escrito la placa." >&2;exit 1;
}
echo "Instalando bootloader, particiones y aplicación Wav32..."
"$ESPTOOL" --chip esp32 --port "$PORT" --baud 115200 --before no-reset \
  --after hard-reset write-flash --flash-mode keep --flash-freq keep \
  --flash-size keep 0x1000 "$BOOT" 0x8000 "$PART" 0x10000 "$APP"
echo "Grabación verificada. Desconecta GPIO0 de GND y presiona RESET."
echo "Consulta el monitor serial a 115200 para obtener SSID, clave WPA2 y clave admin."
