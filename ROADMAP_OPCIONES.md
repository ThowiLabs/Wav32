# Wav32 — Lista de opciones avanzadas propuestas (2026-11-07)

Verificadas contra el core Arduino-ESP32 3.3.12 instalado en Dex, el panel actual
de Wav32 0.2.1 y el proyecto de referencia `/root/esp32_nat_router_reference`.

## Solicitadas

### 1. Panel en http://esp.local desde AMBAS redes — mDNS
- Librería `ESPmDNS` incluida en el core: `MDNS.begin("esp")` + servicio http/80.
- Desde la red Wav32: directo. Desde la red superior: hoy el firmware BLOQUEA la
  administración desde WAN a propósito (`connectedToLAN()`). Para cumplir lo pedido
  hace falta un interruptor nuevo "Administración desde la red superior" (apagado por
  defecto; encenderlo solo si la red superior es de confianza, p. ej. la de casa).
- Nota: "esp" es genérico; si hubiera dos Wav32, chocarían. Se puede hacer configurable.

### 2. Aislamiento respecto a la red superior (conocido a veces como "modo WISP")
- Aclaración: **WISP ya es el modo actual de Wav32** (recibe internet por Wi-Fi y lo
  reparte con NAT; el panel ya lo marca "Activo"). Lo que se busca es otra cosa:
  **aislamiento de la red superior**: los clientes de Wav32 salen a internet pero NO
  pueden ver ni tocar los equipos de la red a la que Wav32 se conecta (impresoras,
  PCs, NAS del anfitrión). Es el modo "invitados/travel router" de los routers de viaje.
- Viabilidad: el NAT por sí solo no lo hace (un cliente sí puede marcar la IP de un
  equipo superior y el NAT lo traduce). Se implementa con hooks de entrada lwIP como
  los de la referencia (`netif_hooks.c`): descartar paquetes LAN→red-superior-privada
  excepto gateway/DNS. Esfuerzo medio, patrón probado en la referencia.
- Variante hermana: **aislamiento entre clientes** de Wav32 (que no se vean entre sí,
  solo salgan a internet). ESP-IDF no trae interruptor de "AP isolation"; también
  saldría de los mismos hooks.

### 3. DNS sugeridos (presets en el panel)
Hoy el DNS es un campo libre (default 1.1.1.1). Agregar selector con:
- Automático (el del router superior, copiado al obtener IP — opción NUEVA, útil)
- Cloudflare 1.1.1.1 · Cloudflare anti-malware 1.1.1.2 · Cloudflare familias 1.1.1.3
- AdGuard 94.140.14.14 · AdGuard familiar 94.140.14.15 (bloquea anuncios a nivel red)
- Quad9 9.9.9.9 (anti-malware) · Google 8.8.8.8 · OpenDNS 208.67.222.222 / FamilyShield 208.67.222.123
- Personalizado (el campo actual)
- Aclaración: "cloudflared" es el programa que cifra DNS (DoH) en un PC/servidor; en el
  ESP32 no corre, pero elegir 1.1.1.1 es justo el DNS de Cloudflare. DoH real dentro del
  ESP32 sería experimental y pesado; no se propone por ahora.

## Propuestas adicionales (de la referencia y del core, filtradas por viabilidad)

### Paquete fácil / alto valor
- **Portal cautivo de bienvenida**: al conectarse a Wav32, el teléfono abre solo la
  página de configuración (DNSServer está en el core). Ideal para el primer uso.
- **Varias redes superiores guardadas con prioridad/failover**: si falla la principal,
  salta a la siguiente (casa → hotspot del celular). Muy de travel router.
- **Watchdog de internet**: ping periódico a gateway/DNS; si no hay salida real,
  reconecta o reinicia solo. Habría detectado solo el fallo de la 0.2.0.
- **Importar respaldo**: hoy se puede descargar el backup JSON pero no restaurarlo.
- **Potencia TX ajustable** y ancho de canal HT40: dos controles baratos del core.

### Paquete medio
- **Reservas DHCP**: IP fija por MAC (la referencia lo hace; Wav32 lo lista como pendiente).
- **Actualización desde el panel (OTA web)**: la librería Update está, pero la tabla de
  particiones actual tiene UN solo slot de app (app0 de 3 MB). OTA real exige reparticionar
  a dos slots (~1.5 MB c/u; la app actual ocupa 1.02 MB, cabe) y una grabación USB completa
  más. A partir de ahí, las siguientes versiones se instalan desde el navegador.
- **Horario por dispositivo**: internet por MAC solo en ciertas horas (extiende el
  sistema de listas y el reloj NTP que ya existen).
- **Diagnósticos en el panel**: ping a gateway/internet y estado por paso
  (asociado → con IP → gateway responde → DNS resuelve → internet responde).

### Grandes / no por ahora
- **WireGuard**: la referencia lo trae como componente IDF; en Arduino no hay librería
  en el core y meterlo es un proyecto aparte. Posible, pero caro.
- **WPA2-Enterprise en el uplink** (redes de oficina/universidad): el core lo soporta
  (EAP), faltan los campos en el panel. Solo si se necesita.
- **MQTT / Home Assistant**: la referencia publica telemetría; nicho.
- **Segundo SSID de invitados**: NO posible — una sola interfaz AP por radio.
- **Wi-Fi 5 GHz / puente capa 2**: imposibles en este hardware/modo, como ya dice el panel.

## Orden sugerido
1. Paquete 1: esp.local (ambas redes, con interruptor) + presets DNS + DNS automático.
2. Paquete 2: aislamiento de red superior + aislamiento entre clientes + reservas DHCP.
3. Paquete 3: OTA con repartición + multi-uplink con failover + watchdog.
