#!/usr/bin/env python3
from html.parser import HTMLParser
from pathlib import Path
import gzip,re
ROOT=Path(__file__).resolve().parents[1]
html=(ROOT/"web/index.html").read_text()
code=(ROOT/"firmware/Wav32/Wav32.ino").read_text()
gen=(ROOT/"firmware/Wav32/ui_gzip.h").read_text()
class Parser(HTMLParser):
    def __init__(self):
        super().__init__();self.ids=[];self.urls=[];self.in_js=False;self.js=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if 'id' in a:self.ids.append(a['id'])
        if tag in ('script','link') and ('src' in a or 'href' in a):self.urls.append(a)
        if tag=='script' and 'src' not in a:self.in_js=True
    def handle_endtag(self,tag):
        if tag=='script':self.in_js=False
    def handle_data(self,data):
        if self.in_js:self.js.append(data)
p=Parser();p.feed(html);js='\n'.join(c for c in p.js if 'Skipped minification' not in c[:300])  # Chart.js integrado no se analiza
assert len(p.ids)==len(set(p.ids))
for u2 in p.urls:
    src2=u2.get('src') or u2.get('href') or ''
    assert not src2.startswith('http'), 'No usar recursos web externos'
for ident in re.findall(r'\bel\("([A-Za-z0-9_-]+)"\)',js):
    assert ident in p.ids, f'Falta elemento {ident}'
for endpoint in re.findall(r'["\'](/api/[a-z_-]+)',js):
    assert f'"{endpoint}"' in code, f'Ruta faltante: {endpoint}'
for page in ['home','terminal','uplink','myap','advanced','security','device']:
    assert f'id="page-{page}"' in html and f'data-go="{page}"' in html
raw=bytes(int(x,16) for x in re.findall(r'0x([a-f0-9]{2})',gen))
assert gzip.decompress(raw)==html.encode(), 'Header UI obsoleto'
for evidence in ['WiFi.AP.enableNAPT(true)','WiFi.softAPConfig(','WiFi.softAP(','WiFi.begin(','WiFi.softAPgetStationNum()','server.client().localIP()==WiFi.softAPIP()','server.header("X-Wav32")!="1"','mbedtls_sha256(','prefs.putInt("lastrday",day)','ip_portmap_add','ip_portmap_remove']:
    assert evidence in code, f'Falta {evidence}'
assert 'NUNCA incluir contraseñas Wi-Fi' in code
print(f'TEST OK: {len(p.ids)} IDs, {len(raw)} bytes HTML gzip, NAT, DHCP, WAN, seguridad.')

# Regresión: el código antiguo ip!=(uint32_t)0 seleccionaba un comparador
# IPAddress de puntero nulo y producía Guru Meditation / LoadProhibited.
assert 'ip!=(uint32_t)0' not in code, 'Regresión: comparación IPAddress con NULL'
assert 'return (ip[0] | ip[1] | ip[2] | ip[3]) != 0;' in code

# Primer arranque de Wi-Fi abierto, sin contraseña preestablecida ni usuario
# administrador inaccesible. La administración queda protegida tras activación.
assert 'cfg.apProtected=prefs.getBool("approtect",false);' in code
assert 'cfg.apProtected?cfg.apPassword.c_str():nullptr' in code
assert 'prefs.remove("appass")' in code, 'Migración debe limpiar contraseñas previas'
assert 'cfg.apPassword=makeSecret(' not in code, 'Wi-Fi de primer uso no debe tener clave'
assert 'prefs.getBool("admClaim",false)' in code
assert 'static void routeInitialSetup()' in code
assert 'server.on("/api/setup",HTTP_POST,routeInitialSetup);' in code
assert 'if(cfg.adminClaimed){apiError(409,' in code, 'El setup no debe repetirse'
assert 'if(!connectedToLAN()){apiError(403,"Solo desde la red local Wav32");return;}' in code
assert 'prefs.putBool("admClaim",true)' in code
assert 'FIRST_SETUP' in code and 'Crear administrador' in code
assert 'id="apSecurity"' in html and 'id="apPassFields"' in html
assert 'protected:el("apSecurity").value==="wpa2"' in html
print("TEST OK: Wi-Fi inicialmente abierto y alta de administrador local protegida")

# Regresion 0.2.1: sin internet tras conectar al uplink.
# a) WiFi.config(INADDR_NONE,...) en el core 3.3.12 fija 255.255.255.255 como
#    IP estatica y apaga DHCP: la STA nunca obtiene IP/gateway/DNS reales.
assert 'WiFi.config(INADDR_NONE,INADDR_NONE,INADDR_NONE)' not in code, 'Regresion: INADDR_NONE no vuelve a DHCP en core 3.x'
assert 'WiFi.config(IPAddress(0,0,0,0),IPAddress(0,0,0,0),IPAddress(0,0,0,0))' in code, 'DHCP debe pedirse con 0.0.0.0'
# b) NAPT debe activarse al obtener IP (patron WiFiExtender oficial), no solo
#    una vez en el arranque, y reactivarse si el AP cicla.
assert 'ARDUINO_EVENT_WIFI_STA_GOT_IP' in code, 'Falta handler STA_GOT_IP para NAPT'
assert 'ARDUINO_EVENT_WIFI_AP_START' in code, 'Falta reactivar NAPT en AP_START'
assert 'Network.onEvent(onNetworkEvent)' in code, 'Falta registrar el handler de red'
assert code.count('WiFi.AP.enableNAPT(true)')>=2, 'NAPT debe activarse en arranque y en GOT_IP'
assert 'static void restoreMappings()' in code, 'Las reglas portmap deben restaurarse tras activar NAPT'
print("TEST OK: DHCP con 0.0.0.0 y NAPT reactivado en GOT_IP/AP_START (0.2.1)")

# --- Wav32 0.3.0: opciones avanzadas (antirregresión) ---
CODE30 = code + "\n" + html
for needle in (
    'MDNS.begin("esp")',
    'MDNS.addService("http","tcp",80)',
    "dnsCaptive.start(53",
    "dropByIsolation",                    # aislamiento por hook lwIP
    "wav32ApInputHook",
    "esp_netif_get_netif_impl",
    "isoUpstream",
    "isoClients",
    "dnsAuto",                            # DNS automatico del uplink
    "94.140.14.14",                       # preset AdGuard en el panel
    "1.1.1.3",                            # preset Cloudflare familias
    "wanAdmin",                           # administracion desde red superior (opcional)
    "esp_ping_new_session",               # watchdog de internet
    "pollWatchdog",
    "upnets",                             # varias redes superiores
    "Failover",
    "Update.begin(UPDATE_SIZE_UNKNOWN",   # OTA web
    '"/api/ota"',
    '"/api/isolation"',
    '"/api/guest"',
    '"/api/restore"',
    '"/api/toggles"',
    "guestMode",                          # modo invitado en la red unica
    "requesterMac",
    "WIFI_POWER_19_5dBm",                 # potencia TX ajustable
    '"/generate_204"',                    # sondas de portal cautivo
    "0.3.0",
):
    assert needle in CODE30, f"Falta en 0.3.0: {needle}"
assert 'INADDR_NONE,INADDR_NONE,INADDR_NONE' not in code
print("TEST OK: 0.3.0 (esp.local, cautivo, aislamiento, DNS, failover, watchdog, OTA, invitado)")

# --- Wav32 0.3.1: defaults seguros de red (antirregresión del corte de internet) ---
assert 'getBool("dnsauto",false)' in code, 'dnsAuto debe venir APAGADO por defecto'
assert 'getBool("watchdog",false)' in code, 'watchdog debe venir APAGADO por defecto'
assert '"setver"' in code, 'Falta la migración de defaults 0.3.1'
assert code.count('WiFi.disconnect();connectUpstream();')==1, \
    'WiFi.disconnect()+connectUpstream solo puede vivir en el failover, no en el watchdog'
assert 'wdFails==6' in code and 'WiFi.reconnect();' in code
print("TEST OK: 0.3.1 (DNS fijo por defecto, migracion, watchdog por rondas)")

# --- Wav32 0.4.0: panel nuevo y bloqueo avanzado (antirregresión) ---
for needle in ('"/api/block"','"/api/kick"','Has sido bloqueado','blockedList',
               'blkMsg','dnsBlockActive','pollDnsProxy','syncDnsProxy',
               'serveBlockedPage','Wav32 0.4.0','Bloqueo avanzado','id="page-uplink"',
               'id="page-myap"','temperatureRead'):
    assert needle in CODE30, f"Falta en 0.4.0: {needle}"
assert 'cdn.jsdelivr' not in html and 'fonts.googleapis' not in html, \
    'El panel real debe ser autocontenido (Chart.js va integrado)'
print("TEST OK: 0.4.0 (panel nuevo autocontenido y bloqueo avanzado con DNS)")

# --- Wav32 0.4.1: Chart.js como asset propio cacheable ---
for needle in ('"/chart.js"','serveGzip','WAV32_CHART_GZIP'):
    assert needle in CODE30, f"Falta en 0.4.1: {needle}"
print("TEST OK: 0.4.1 (UI en streaming y Chart.js cacheable aparte)")

# --- Wav32 0.4.2: acceso con diseno, movil y red superior ---
for needle in ('"/api/login"','"/api/logout"','LOGIN_HTML','WAV32SID','routeLogin',
               'serveLoginPage','credentialsOK','id="menuBtn"','Cerrar sesión',
               'pass.length()<4||pass.length()>64','setver",0)<3'):
    assert needle in CODE30, f"Falta en 0.4.2: {needle}"
assert ('sendHeader(' + chr(34) + 'WWW-Authenticate') not in code, 'Sin dialogos del navegador'
print("TEST OK: 0.4.2 (login con diseno, panel movil y esp.local desde red superior)")


# --- Wav32 0.4.3: modal de clave Wi-Fi y Chart.js integro ---
for needle in ('function askConfirm(title,text,okLabel,cb,needText,placeholder)',
               "inp.dataset.need=placeholder?'':needText"):
    assert needle in CODE30, f"Falta en 0.4.3: {needle}"
chart=(ROOT/"web/chart.umd.min.js").read_bytes()
assert b'Skipped minification' not in chart, \
    'Chart.js de jsdelivr esta roto en Chromium (SyntaxError: Identifier a); usar el build minificado integro'
genchart=(ROOT/"firmware/Wav32/ui_chart_gzip.h").read_text()
rawchart=bytes(int(x,16) for x in re.findall(r'0x([a-f0-9]{2})',genchart))
assert gzip.decompress(rawchart)==chart, 'Header Chart.js obsoleto'
print("TEST OK: 0.4.3 (clave Wi-Fi sin palabra exacta y Chart.js integro)")


# --- Wav32 0.4.4: chart.js con version en la URL (rompe la cache vieja) ---
for needle in ('chart.js?v=044'):
    assert needle in CODE30, f"Falta en 0.4.4: {needle}"
print("TEST OK: 0.4.4 (URL de Chart.js versionada)")


# --- Wav32 0.4.5: bloqueo sin candados (sin excepciones) ---
assert 'No puedes bloquear el dispositivo del dueno' not in CODE30,     '0.4.5 quita el candado del dueno en routeBlock'
assert 'No puedes bloquear el dispositivo desde el que administras' not in CODE30,     '0.4.5 quita el candado del administrador en routeBlock'
print("TEST OK: 0.4.5 (bloqueo permitido tambien al dueno y al administrador)")


# --- Wav32 0.4.6: repo publico sin referencias personales ---
assert 'Wav32 0.4.6' in CODE30, "Falta en 0.4.6: version"
for personal in ('Thowi'+'Labs', '24:'+'DC:'+'C3', 'C3DC'+'24'):
    assert personal not in CODE30, f"Referencia personal en el repo: {personal}"
assert 'id="devMacSta"' in html and 'ST.wanMac' in html,     'La MAC STA del panel debe salir de /api/status, no ir escrita en el HTML'
print("TEST OK: 0.4.6 (README publico y repo sin referencias personales)")
