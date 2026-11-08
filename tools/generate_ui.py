#!/usr/bin/env python3
"""Genera UI HTML autocontenida, comprimida dentro de la flash del ESP32."""
from pathlib import Path
import gzip
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'web/index.html').read_bytes()
payload=gzip.compress(source, compresslevel=9, mtime=0)
lines=[]
for i in range(0,len(payload),20):
    lines.append('  '+','.join('0x%02x'%b for b in payload[i:i+20])+',')
header='''#pragma once
#include <stddef.h>
#include <stdint.h>
// Archivo generado por tools/generate_ui.py. No editar a mano.
static const uint8_t WAV32_UI_GZIP[] PROGMEM={
'''+('\n'.join(lines))+'''
};
static const size_t WAV32_UI_GZIP_LEN=sizeof(WAV32_UI_GZIP);
'''
(ROOT/'firmware/Wav32/ui_gzip.h').write_text(header)
print('UI HTML:',len(source),'bytes; gzip:',len(payload),'bytes')
# Chart.js como asset aparte y cacheable (/chart.js): fuera del HTML
# principal para que el panel cargue rapido como en <=0.3.2.
csource=(ROOT/'web/chart.umd.min.js').read_bytes()
cpayload=gzip.compress(csource, compresslevel=9, mtime=0)
clines=[]
for i in range(0,len(cpayload),20):
    clines.append('  '+','.join('0x%02x'%b for b in cpayload[i:i+20])+',')
cheader='''#pragma once
#include <stddef.h>
#include <stdint.h>
// Archivo generado por tools/generate_ui.py. No editar a mano.
static const uint8_t WAV32_CHART_GZIP[] PROGMEM={
'''+('\n'.join(clines))+'''
};
static const size_t WAV32_CHART_GZIP_LEN=sizeof(WAV32_CHART_GZIP);
'''
(ROOT/'firmware/Wav32/ui_chart_gzip.h').write_text(cheader)
print('Chart JS:',len(csource),'bytes; gzip:',len(cpayload),'bytes')
