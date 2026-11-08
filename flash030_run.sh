#!/bin/sh
cd /root/Wav32 || exit 1
ESP=/root/.platformio/packages/tool-esptool/esptool
PORT=/dev/ttyUSB0
LOG=/root/Wav32/backups/flasheo-wav32-030-borrado-20261107.log
: > "$LOG"
echo "=== WAV32 0.3.0 CON BORRADO TOTAL ===" >> "$LOG"
date >> "$LOG"
sha256sum build/Wav32.ino.bin build/Wav32.ino.bootloader.bin build/Wav32.ino.partitions.bin >> "$LOG"
"$ESP" --chip esp32 --port "$PORT" --before no_reset --after no_reset erase-flash >> "$LOG" 2>&1
E=$?
echo "ERASE_EXIT:$E" >> "$LOG"
if [ $E -ne 0 ]; then echo "FLASH030_DONE:ERASE_FAIL" >> "$LOG"; exit 0; fi
"$ESP" --chip esp32 --port "$PORT" --before no_reset --after no_reset write-flash -z --flash_mode dio --flash_freq 40m --flash_size detect 0x1000 build/Wav32.ino.bootloader.bin 0x8000 build/Wav32.ino.partitions.bin 0x10000 build/Wav32.ino.bin >> "$LOG" 2>&1
W=$?
echo "WRITE_EXIT:$W" >> "$LOG"
if [ $W -ne 0 ]; then echo "FLASH030_DONE:WRITE_FAIL" >> "$LOG"; exit 0; fi
"$ESP" --chip esp32 --port "$PORT" --before no_reset --after no_reset verify-flash 0x1000 build/Wav32.ino.bootloader.bin 0x8000 build/Wav32.ino.partitions.bin 0x10000 build/Wav32.ino.bin >> "$LOG" 2>&1
V=$?
echo "VERIFY_EXIT:$V" >> "$LOG"
if [ $V -eq 0 ]; then echo "FLASH030_DONE:OK" >> "$LOG"; else echo "FLASH030_DONE:VERIFY_FAIL" >> "$LOG"; fi
