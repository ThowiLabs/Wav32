# Wav32

Firmware que convierte una ESP32-CAM AI-Thinker en un router Wi-Fi: se conecta a una red 2.4 GHz existente y reparte internet a su propia red mediante NAT, con panel de administración web servido desde la propia placa. La cámara y la microSD no se utilizan.

## Qué hace

- Red propia `Wav32-XXXXXX`: arranca abierta y puede asegurarse con WPA2 desde el panel.
- Hasta 3 redes superiores guardadas, con failover a los 60 s sin enlace.
- WAN por DHCP o IP fija; DNS con presets (Cloudflare, AdGuard, Quad9, Google, OpenDNS) o personalizado.
- Panel en `http://192.168.32.1` y `http://esp.local`; acceso opcional también desde la red superior.
- Acceso con contraseña de administrador (hash SHA-256 con salt en NVS) y sesión por cookie. La página de acceso es propia, sin diálogos del navegador.
- Clientes conectados con IP, MAC y señal; expulsión temporal y bloqueo persistente: el dispositivo bloqueado se sigue conectando y obtiene IP, pero su navegación cae en una página «Has sido bloqueado» con mensaje editable.
- Redirección de puertos TCP/UDP (máx. 8 reglas) y listas de acceso por MAC.
- Modo invitado sobre la misma red: contraseña temporal y panel visible solo para el dispositivo dueño.
- Respaldo y restauración de la configuración en JSON, sin contraseñas.
- Actualización de firmware desde el panel (OTA, dos ranuras), reinicio programado diario, watchdog de conexión (desactivado por defecto) y potencia de transmisión ajustable.

## Limitaciones

- Una sola radio de 2.4 GHz compartida entre el enlace superior y la red propia: el rendimiento total es el de esa radio.
- Es un router NAT (modo WISP), no un puente de capa 2: las dos redes son subredes distintas.
- Sin 5 GHz, PPPoE, WAN por cable, IPv6, VLAN ni VPN.
- Sin reservas DHCP: el firmware de red no ofrece una API para fijar concesiones por MAC.
- El bloqueo de dispositivos actúa a nivel DNS/web: un cliente con DNS cifrado (DoH) o que navegue por IP directa puede saltarse la página de bloqueo.
- Las opciones de aislamiento entre clientes y hacia la red superior están en el panel, pero no se aplican en la ruta de datos actual.
- El panel es HTTP sin cifrar: úsalo en redes de confianza.

## Compilar

Requisitos: Arduino CLI con el core ESP32 3.3.12 y Python 3.

    ./tools/build.sh

Ejecuta las pruebas de `tests/validate.py`, regenera la interfaz web comprimida y compila. Los binarios quedan en `build/`: `Wav32.ino.bin`, `Wav32.ino.bootloader.bin` y `Wav32.ino.partitions.bin`.

## Instalación por USB

La primera instalación escribe el bootloader, la tabla de particiones (dos ranuras, necesaria para OTA) y la aplicación. Con la placa en modo descarga (GPIO0 a GND y RESET):

    esptool --chip esp32 --port /dev/ttyUSB0 --baud 460800 write-flash \
      0x1000 build/Wav32.ino.bootloader.bin \
      0x8000 build/Wav32.ino.partitions.bin \
      0x10000 build/Wav32.ino.bin

`tools/flash-second.sh` hace lo mismo con dos seguridades: guarda un respaldo completo de la flash antes de escribir y puede abortar si la placa tiene una MAC que quieras proteger (variable `PROTECTED_MAC`). Tras grabar, retira el puente y reinicia.

## Primer arranque

1. Conéctate a la red abierta `Wav32-XXXXXX`.
2. Abre `http://192.168.32.1` y crea la contraseña de administrador (mínimo 4 caracteres).
3. En «Red superior» elige tu red Wi-Fi y guarda. La placa se reinicia y se conecta.

Los clientes de la red Wav32 reciben direcciones desde 192.168.32.100; el octeto de la LAN es configurable.

## Actualizar

Desde el panel, en Dispositivo: sube el archivo `Wav32.ino.bin` nuevo. La actualización se escribe en la ranura libre y la placa reinicia; la configuración se conserva en NVS.

## Estructura

- `firmware/Wav32/Wav32.ino` — firmware completo.
- `web/index.html` — panel (HTML/CSS/JS; Chart.js se sirve aparte desde la flash).
- `tools/` — compilación, generación de la interfaz y flasheo.
- `tests/validate.py` — comprobaciones de regresión.
- `ROADMAP_OPCIONES.md` — ideas y estado de funciones.

## Licencia

MIT. Ver `LICENSE`.
