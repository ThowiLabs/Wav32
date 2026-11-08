/*
 * Wav32 — Router NAT Wi-Fi para ESP32-CAM (AI-Thinker, sin cámara ni microSD).
 * Firmware propio; estructura de administración inspirada por el WAVLINK local.
 * Requiere Arduino-ESP32 3.3.12 (ESP-IDF NAPT habilitado).
 */
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <lwip/lwip_napt.h>
#include <lwip/sockets.h>
#include <esp_wifi_ap_get_sta_list.h>
#include <ESPmDNS.h>
#include <DNSServer.h>
#include <Update.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include "ping/ping_sock.h"
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>
#include <esp_system.h>
#include <time.h>
#include "ui_gzip.h"
#include "ui_chart_gzip.h"

static const char* FW_VERSION="Wav32 0.4.6";
static WebServer server(80);
static Preferences prefs;
static const uint8_t LED_PIN=4;
static const char* HEADERS[]={"Authorization","X-Wav32","Cookie"};
static String sessionToken="";
static uint8_t loginFails=0;
static uint32_t loginLockUntil=0;
static const uint32_t RECONNECT_MS=15000;
static const uint32_t CLIENT_CHECK_MS=3000;
static const uint32_t STATUS_MS=2000;
static bool natActive=false;
static bool staHasIp=false;
static bool ledOn=false;
static uint32_t rebootAt=0, lastReconnect=0, lastClientCheck=0, lastStatus=0;
static int32_t lastRebootDay=-1;
static String configWarning;
static DNSServer dnsCaptive;
static bool captiveOn=false;
static IPAddress staIpNow,staMaskNow,staGwNow,staDnsNow;
static uint32_t dropUpCount=0,dropCliCount=0;
static esp_ping_handle_t wdSession=nullptr;
static volatile bool wdPingOk=false,wdPingDone=false;
static uint8_t wdFails=0,wdCycle=0;
static bool wdGwOk=false,wdGwDone=false,wdLastGw=false;
static uint32_t lastWatchdog=0,staDropSince=0;

struct Settings {
  String apSsid, apPassword, upstreamSsid, upstreamPassword;
  String adminSalt, adminHash;
  String dns="1.1.1.1";
  String wanIP, wanGateway, wanMask, wanDNS2;
  uint8_t lanOctet=32, channel=6, maxClients=5;
  bool apHidden=false, apProtected=false, adminClaimed=false, wanStatic=false, ledEnabled=false;
  bool dailyReboot=false;
  bool dnsAuto=false,wanAdmin=false,isoUpstream=false,isoClients=false;
  bool guestMode=false,watchdog=false,guestPrevProtected=false;
  String guestPrevPass,ownerMac;
  uint8_t txPowerIdx=0;
  uint8_t rebootHour=4, rebootMinute=0;
  int16_t utcOffsetMinutes=-360;
  String macMode="off", macList="";
  String blockedList=""; String blkMsg="";
} cfg;

struct ForwardRule {
  bool tcp;
  uint16_t externalPort;
  IPAddress dest;
  uint16_t internalPort;
};
static ForwardRule rules[8];
static size_t ruleCount=0;

struct UpNet { String ssid,pass; bool open=false; };
static UpNet upnets[3];
static uint8_t upnetCount=0;
static int8_t upnetTry=0,upnetActive=-1;

static String hexBytes(const uint8_t* data, size_t len) {
  static const char h[]="0123456789abcdef";
  String out; out.reserve(len*2);
  for(size_t i=0;i<len;i++) {out+=h[data[i]>>4];out+=h[data[i]&15];}
  return out;
}
static String makeSecret(size_t len) {
  const char alphabet[]="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  String x; x.reserve(len);
  for(size_t i=0;i<len;i++) x+=alphabet[esp_random()%(sizeof(alphabet)-1)];
  return x;
}
static String saltedHash(const String& salt,const String& pass) {
  const String data=salt+":"+pass;
  uint8_t digest[32];
  if(mbedtls_sha256((const unsigned char*)data.c_str(),data.length(),digest,0)!=0) return "";
  return hexBytes(digest,32);
}
static bool equalHash(const String& a,const String& b) {
  if(a.length()!=b.length()) return false;
  uint8_t d=0;for(size_t i=0;i<a.length();i++) d|=(uint8_t)(a[i]^b[i]);
  return d==0;
}
static bool adminPasswordOK(const String& pass) {
  return equalHash(saltedHash(cfg.adminSalt,pass),cfg.adminHash);
}
static void updateAdmin(const String& pass) {
  uint8_t salt[16];esp_fill_random(salt,sizeof(salt));
  cfg.adminSalt=hexBytes(salt,sizeof(salt));
  cfg.adminHash=saltedHash(cfg.adminSalt,pass);
  prefs.putString("admSalt",cfg.adminSalt);
  prefs.putString("admHash",cfg.adminHash);
}
static IPAddress apIP() {return IPAddress(192,168,cfg.lanOctet,1);}
static IPAddress apMask() {return IPAddress(255,255,255,0);}
static IPAddress dhcpStart() {return IPAddress(192,168,cfg.lanOctet,100);}
static bool validSSID(const String& ssid){return ssid.length()>0 && ssid.length()<=32;}
static bool validPass(const String& p){return p.length()>=8 && p.length()<=63;}
static bool validIPv4(const String& value) {
  // Importante: IPAddress != (uint32_t)0 selecciona la sobrecarga con
  // uint8_t* y desreferencia NULL: provocaba LoadProhibited al arrancar.
  // Exigimos IPv4 decimal con exactamente 3 puntos y descartamos 0.0.0.0.
  if (value.length()<7 || value.length()>15) return false;
  uint8_t dots=0;
  for (size_t i=0;i<value.length();++i) {
    const char c=value[i];
    if(c=='.') ++dots;
    else if(c<'0'||c>'9') return false;
  }
  if(dots!=3) return false;
  IPAddress ip;
  if(!ip.fromString(value)) return false;
  return (ip[0] | ip[1] | ip[2] | ip[3]) != 0;
}
static bool validMAC(String m) {
  m.trim();
  if(m.length()!=17)return false;
  for(int i=0;i<17;i++){
    if(i%3==2){if(m[i]!=':')return false;}
    else if(!isxdigit((unsigned char)m[i]))return false;
  }
  return true;
}
static String normalizeMAC(String m) {m.trim();m.toUpperCase();return m;}
static bool validMACList(const String& list) {
  if(list.length()>390)return false;
  String s=list; s.replace("\r","");
  size_t count=0;int start=0;
  while(start<(int)s.length()){
    int end=s.indexOf('\n',start);if(end<0)end=s.length();
    String m=s.substring(start,end);m.trim();
    if(m.length() && (!validMAC(m)||++count>16))return false;
    start=end+1;
  }
  return true;
}
static bool macAllowed(String mac) {
  if(cfg.macMode=="off") return true;
  mac=normalizeMAC(mac);
  const String padded="\n"+cfg.macList+"\n";
  const bool listed=padded.indexOf("\n"+mac+"\n")>=0;
  return cfg.macMode=="allow"?listed:!listed;
}
static bool macBlocked(String mac){
  if(cfg.blockedList.isEmpty())return false;
  mac=normalizeMAC(mac);
  const String padded="\n"+cfg.blockedList+"\n";
  return padded.indexOf("\n"+mac+"\n")>=0;
}
static int blockedCount(){
  if(cfg.blockedList.isEmpty())return 0;
  int n=1;
  for(size_t i=0;i<cfg.blockedList.length();i++)if(cfg.blockedList[i]=='\n')n++;
  return n;
}
static bool parseMAC(const String& s,uint8_t out[6]){
  unsigned int b[6];
  if(sscanf(s.c_str(),"%02x:%02x:%02x:%02x:%02x:%02x",&b[0],&b[1],&b[2],&b[3],&b[4],&b[5])!=6)return false;
  for(int i=0;i<6;i++)out[i]=(uint8_t)b[i];
  return true;
}
static void deauthMac(const String& mac){
  uint8_t raw[6];if(!parseMAC(mac,raw))return;
  uint16_t aid=0;
  if(esp_wifi_ap_get_sta_aid(raw,&aid)==ESP_OK&&aid)esp_wifi_deauth_sta(aid);
}
static String macOfIP(const IPAddress& ip){
  wifi_sta_list_t sta={};wifi_sta_mac_ip_list_t ips={};
  if(esp_wifi_ap_get_sta_list(&sta)==ESP_OK&&
     esp_wifi_ap_get_sta_list_with_ip(&sta,&ips)==ESP_OK)
    for(int i=0;i<ips.num;i++)
      if(IPAddress(ips.sta[i].ip.addr)==ip)return formatMAC(ips.sta[i].mac);
  return "";
}
static void loadRules() {
  ruleCount=0;String json=prefs.getString("ports","[]");
  DynamicJsonDocument doc(1500);
  if(deserializeJson(doc,json))return;
  for(JsonVariant v: doc.as<JsonArray>()){
    if(ruleCount>=8)break;
    String ip=v["ip"].as<String>();IPAddress addr;
    int ext=v["ext"]|0, in=v["in"]|0;bool tcp=v["tcp"]|true;
    if(addr.fromString(ip) && ext>0 && ext<=65535 && in>0 && in<=65535)
      rules[ruleCount++]={tcp,(uint16_t)ext,addr,(uint16_t)in};
  }
}
static void saveRules() {
  DynamicJsonDocument doc(1500);
  JsonArray arr=doc.to<JsonArray>();
  for(size_t i=0;i<ruleCount;i++){
    JsonObject o=arr.createNestedObject();
    o["tcp"]=rules[i].tcp;o["ext"]=rules[i].externalPort;
    o["ip"]=rules[i].dest.toString();o["in"]=rules[i].internalPort;
  }
  String s;serializeJson(doc,s);prefs.putString("ports",s);
}
static void loadUpnets(){
  upnetCount=0;upnetTry=0;upnetActive=-1;
  String raw=prefs.getString("upnets","");
  if(!raw.isEmpty()){
    DynamicJsonDocument doc(1400);
    if(!deserializeJson(doc,raw)){
      JsonArray arr=doc.as<JsonArray>();
      for(JsonObject o:arr){
        if(upnetCount>=3)break;
        String ss=o["ssid"]|String("");
        if(ss.isEmpty())continue;
        upnets[upnetCount].ssid=ss;
        upnets[upnetCount].pass=o["pass"]|String("");
        upnets[upnetCount].open=o["open"]|false;
        upnetCount++;
      }
    }
  }
  if(upnetCount==0 && !cfg.upstreamSsid.isEmpty()){
    upnets[0].ssid=cfg.upstreamSsid;upnets[0].pass=cfg.upstreamPassword;
    upnets[0].open=cfg.upstreamPassword.isEmpty();upnetCount=1;
  }
}
static void saveUpnets(){
  DynamicJsonDocument doc(1400);JsonArray arr=doc.to<JsonArray>();
  for(int i=0;i<upnetCount;i++){
    JsonObject o=arr.createNestedObject();
    o["ssid"]=upnets[i].ssid;o["pass"]=upnets[i].pass;o["open"]=upnets[i].open;
  }
  String s;serializeJson(doc,s);prefs.putString("upnets",s);
  prefs.putString("stassid",upnetCount?upnets[0].ssid:String(""));
  prefs.putString("stapass",upnetCount?upnets[0].pass:String(""));
}
static void loadSettings() {
  if(!prefs.begin("wav32",false)){Serial.println("[ERR] NVS no disponible");return;}
  cfg.apSsid=prefs.getString("apssid","");
  cfg.apPassword=prefs.getString("appass","");
  cfg.upstreamSsid=prefs.getString("stassid","");
  cfg.upstreamPassword=prefs.getString("stapass","");
  cfg.adminSalt=prefs.getString("admSalt","");
  cfg.adminHash=prefs.getString("admHash","");
  // Compatibilidad con 0.1.1: las claves ADMIN autogeneradas antiguas
  // nunca se eligieron en el panel y no tienen marca de activación.
  // Al migrar, permitir crearla desde el portal de primer uso.
  cfg.adminClaimed=prefs.getBool("admClaim",false);
  cfg.apProtected=prefs.getBool("approtect",false);
  if(!cfg.apProtected){
    cfg.apPassword="";
    prefs.remove("appass"); // Eliminar contraseñas WLAN previas al migrar
  }
  cfg.dns=prefs.getString("dns","1.1.1.1");
  cfg.wanIP=prefs.getString("wanip","");
  cfg.wanGateway=prefs.getString("wangw","");
  cfg.wanMask=prefs.getString("wanmask","");
  cfg.wanDNS2=prefs.getString("dns2","");
  cfg.wanStatic=prefs.getBool("wanstat",false);
  cfg.lanOctet=prefs.getUChar("lanoct",32);
  cfg.channel=prefs.getUChar("channel",6);
  cfg.maxClients=prefs.getUChar("maxclient",5);
  cfg.apHidden=prefs.getBool("hidden",false);
  cfg.ledEnabled=prefs.getBool("led",false);
  cfg.dailyReboot=prefs.getBool("dreboot",false);
  cfg.rebootHour=prefs.getUChar("rhour",4);
  cfg.rebootMinute=prefs.getUChar("rmin",0);
  cfg.utcOffsetMinutes=prefs.getShort("tzoffset",-360);
  cfg.macMode=prefs.getString("macmode","off");
  cfg.macList=prefs.getString("maclist","");
  cfg.blockedList=prefs.getString("blklist","");
  cfg.blkMsg=prefs.getString("blkmsg","");
  if(cfg.blkMsg.isEmpty())cfg.blkMsg="Este dispositivo ha sido bloqueado por el administrador de la red Wav32. Si crees que es un error, contacta al administrador.";
  lastRebootDay=prefs.getInt("lastrday",-1);
  cfg.dnsAuto=prefs.getBool("dnsauto",false);
  cfg.wanAdmin=prefs.getBool("wanadmin",true);
  sessionToken=prefs.getString("sid","");
  cfg.isoUpstream=prefs.getBool("isoup",false);
  cfg.isoClients=prefs.getBool("isocli",false);
  cfg.guestMode=prefs.getBool("guest",false);
  cfg.watchdog=prefs.getBool("watchdog",false);
  cfg.guestPrevProtected=prefs.getBool("gprevprot",false);
  cfg.guestPrevPass=prefs.getString("gprevpass","");
  cfg.ownerMac=prefs.getString("ownermac","");
  cfg.txPowerIdx=prefs.getUChar("txpow",0);
  if(prefs.getUChar("setver",0)<2){
    // 0.3.1: la 0.3.0 activaba por defecto el DNS automatico (repartia el
    // DNS del router superior, que en muchas redes no responde tras el NAT
    // y dejaba a los clientes sin resolver = "sin internet") y un watchdog
    // por ping que desconectaba aunque el internet real funcionara.
    cfg.dnsAuto=false;cfg.watchdog=false;
    prefs.putBool("dnsauto",false);prefs.putBool("watchdog",false);
    prefs.putUChar("setver",2);
    Serial.println("[WAV32] Migracion 0.3.1: DNS fijo y watchdog desactivado");
  }
  if(prefs.getUChar("setver",0)<3){
    // 0.4.2: el panel queda accesible tambien desde la red superior
    // (esp.local en la Wi-Fi a la que se conecta Wav32); el interruptor
    // sigue existiendo en Seguridad para quien quiera apagarlo.
    cfg.wanAdmin=true;prefs.putBool("wanadmin",true);
    prefs.putUChar("setver",3);
    Serial.println("[WAV32] Migracion 0.4.2: panel accesible desde la red superior");
  }
  if(cfg.txPowerIdx>4)cfg.txPowerIdx=0;
  loadUpnets();
  if(cfg.lanOctet<2||cfg.lanOctet>250)cfg.lanOctet=32;
  if(cfg.channel<1||cfg.channel>11)cfg.channel=6;
  if(cfg.maxClients<1||cfg.maxClients>8)cfg.maxClients=5;
  if(!validIPv4(cfg.dns))cfg.dns="1.1.1.1";
  if(cfg.apSsid.isEmpty()) {
    uint64_t mac=ESP.getEfuseMac();
    char suffix[7];snprintf(suffix,sizeof(suffix),"%06llX",(unsigned long long)(mac&0xFFFFFF));
    cfg.apSsid=String("Wav32-")+suffix;
    prefs.putString("apssid",cfg.apSsid);
  }
  if(cfg.apProtected && !validPass(cfg.apPassword)){
    cfg.apProtected=false;
    cfg.apPassword="";
    prefs.putBool("approtect",false);
    prefs.remove("appass");
  }
  if(!cfg.adminClaimed){
    cfg.adminSalt="";
    cfg.adminHash="";
    prefs.remove("admSalt");
    prefs.remove("admHash");
    Serial.println("[WAV32] Primer uso: crea tu clave admin desde el navegador.");
  }
  Serial.println("[WAV32] SSID: "+cfg.apSsid);
  Serial.println(cfg.apProtected?"[WAV32] Red WPA2":"[WAV32] Red ABIERTA, sin clave WiFi");
  Serial.println("[WAV32] Panel: http://"+apIP().toString());
  loadRules();
}
static String formatMAC(const uint8_t* mac){
  char b[19];snprintf(b,sizeof(b),"%02X:%02X:%02X:%02X:%02X:%02X",
     mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);return String(b);
}
static void applyMappings() {
  if(WiFi.status()!=WL_CONNECTED)return;
  uint32_t wan=(uint32_t)WiFi.localIP();
  for(size_t i=0;i<ruleCount;i++){
    ip_portmap_add(rules[i].tcp?IPPROTO_TCP:IPPROTO_UDP,wan,rules[i].externalPort,
                   (uint32_t)rules[i].dest,rules[i].internalPort);
  }
}
static void restoreMappings() {
  // ip_portmap_add() es un no-op silencioso hasta que NAPT reserva sus
  // tablas; al (re)activar NAPT hay que quitar y volver a poner las reglas,
  // como hace el router NAT de referencia, o quedan perdidas/duplicadas.
  if(WiFi.status()!=WL_CONNECTED)return;
  for(size_t i=0;i<ruleCount;i++)
    ip_portmap_remove(rules[i].tcp?IPPROTO_TCP:IPPROTO_UDP,rules[i].externalPort);
  applyMappings();
}
static void activateNat(const char* why) {
  // NAPT se activa SOLO con IP de uplink ya asignada: es el patrón del
  // ejemplo oficial WiFiExtender del core 3.3.12 (ARDUINO_EVENT_WIFI_STA_GOT_IP)
  // y del proyecto NAT de referencia. Activarlo una sola vez en el arranque,
  // antes de que la STA tenga IP, deja a los clientes del AP sin traducción:
  // se asocian, reciben DHCP y abren el panel, pero no salen a internet.
  if(WiFi.status()!=WL_CONNECTED)return;
  const bool ok=WiFi.AP.enableNAPT(true);
  if(ok||natActive!=ok)
    Serial.printf("[WAV32] NAT %s (%s) WAN %s GW %s DNS %s\n",
                  ok?"ON":"ERROR",why,WiFi.localIP().toString().c_str(),
                  WiFi.gatewayIP().toString().c_str(),WiFi.dnsIP().toString().c_str());
  natActive=ok;
  if(ok)restoreMappings();
}
extern "C" struct netif* esp_netif_get_netif_impl(esp_netif_t* esp_netif);
static netif_input_fn wav32OrigApInput=nullptr;
static bool ipEq4(const uint8_t* a,const IPAddress& b){
  return a[0]==b[0]&&a[1]==b[1]&&a[2]==b[2]&&a[3]==b[3];
}
// Aislamiento pedido por el dueño (patron de hooks de la referencia):
// se inspecciona cada paquete IPv4 que entra por la interfaz AP ANTES de
// que lwIP lo entregue o lo enrute, y se descarta segun las dos reglas.
static bool dropByIsolation(struct pbuf* p){
  if(!p||p->len<20)return false;
  const uint8_t* b=(const uint8_t*)p->payload;
  size_t off=0;
  if((b[0]>>4)!=4){
    if(p->len>=34&&b[12]==0x08&&b[13]==0x00&&(b[14]>>4)==4)off=14;else return false;
  }
  const uint8_t* ip=b+off;
  const uint8_t* src=ip+12;const uint8_t* dst=ip+16;
  IPAddress ap=apIP();
  if(!(src[0]==192&&src[1]==168&&src[2]==cfg.lanOctet))return false;
  if(ipEq4(src,ap))return false;                    // trafico del propio ESP
  if(dst[0]>=224)return false;                      // multicast/broadcast L3
  const bool dstLan=(dst[0]==192&&dst[1]==168&&dst[2]==cfg.lanOctet);
  const bool dstAp=ipEq4(dst,ap);
  if((cfg.isoClients||cfg.guestMode)&&dstLan&&!dstAp){dropCliCount++;return true;}
  if((cfg.isoUpstream||cfg.guestMode)&&staHasIp){
    bool inUp=true;
    for(int i=0;i<4;i++)if( (dst[i]&staMaskNow[i]) != (staIpNow[i]&staMaskNow[i]) )inUp=false;
    if(inUp&&!ipEq4(dst,staIpNow)&&!ipEq4(dst,staGwNow)&&!ipEq4(dst,staDnsNow)){
      dropUpCount++;return true;
    }
  }
  return false;
}
static err_t wav32ApInputHook(struct pbuf* p,struct netif* inp){
  if(dropByIsolation(p)){pbuf_free(p);return ERR_OK;}
  return wav32OrigApInput?wav32OrigApInput(p,inp):ERR_VAL;
}
static void installApHook(){
  esp_netif_t* h=esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if(!h)return;
  struct netif* n=esp_netif_get_netif_impl(h);
  if(!n)return;
  if(n->input!=wav32ApInputHook){wav32OrigApInput=n->input;n->input=wav32ApInputHook;}
}
static IPAddress effectiveDns(){
  if(cfg.dnsAuto&&staHasIp){
    IPAddress d=WiFi.dnsIP();
    if((uint32_t)d!=0)return d;
  }
  IPAddress d;d.fromString(cfg.dns);return d;
}
static bool captiveActive(){ return !cfg.adminClaimed; }
static bool dnsBlockActive(){ return !captiveActive()&&blockedCount()>0; }
static void applyApDns(){
  esp_netif_t* ap=esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if(!ap)return;
  IPAddress d=(captiveActive()||dnsBlockActive())?apIP():effectiveDns();
  esp_netif_dns_info_t info{};
  info.ip.type=ESP_IPADDR_TYPE_V4;info.ip.u_addr.ip4.addr=(uint32_t)d;
  esp_netif_set_dns_info(ap,ESP_NETIF_DNS_MAIN,&info);

}
// --- DNS del bloqueo avanzado (0.4.0) ---
// Con bloqueados activos el DHCP ofrece la propia AP como DNS: al
// bloqueado se le responde todo con la IP de la AP (cae en la pagina de
// bloqueo) y al resto se le reenvia su DNS real. Sin bloqueados este
// servidor no arranca y la ruta DNS queda como en la 0.3.2.
static WiFiUDP dnsUdp;
static WiFiUDP dnsUp;
static bool dnsUdpOn=false;
struct DnsPend{bool used;uint16_t id;IPAddress src;uint16_t port;uint32_t t;};
static DnsPend dnsPend[6];
static void syncDnsProxy(){
  const bool want=dnsBlockActive();
  if(want&&!dnsUdpOn){
    if(dnsUdp.begin(53)){dnsUp.begin(53210);dnsUdpOn=true;
      Serial.println("[WAV32] DNS de bloqueo activo");}
  }
  if(!want&&dnsUdpOn){dnsUdp.stop();dnsUp.stop();dnsUdpOn=false;
    for(int i=0;i<6;i++)dnsPend[i].used=false;
    Serial.println("[WAV32] DNS de bloqueo detenido");}
}
static void pollDnsProxy(){
  if(!dnsUdpOn)return;
  int upn=dnsUp.parsePacket();
  if(upn>0){
    static uint8_t ub[512];int n=dnsUp.read(ub,sizeof(ub));
    if(n>=12){
      const uint16_t id=((uint16_t)ub[0]<<8)|ub[1];
      for(int i=0;i<6;i++)if(dnsPend[i].used&&dnsPend[i].id==id){
        dnsUdp.beginPacket(dnsPend[i].src,dnsPend[i].port);
        dnsUdp.write(ub,n);dnsUdp.endPacket();dnsPend[i].used=false;break;
      }
    }
    return;
  }
  for(int i=0;i<6;i++)
    if(dnsPend[i].used&&millis()-dnsPend[i].t>2500)dnsPend[i].used=false;
  int sz=dnsUdp.parsePacket();
  if(sz<=0)return;
  static uint8_t buf[512];int n=dnsUdp.read(buf,sizeof(buf));
  if(n<12)return;
  const IPAddress src=dnsUdp.remoteIP();const uint16_t sport=dnsUdp.remotePort();
  const String mac=macOfIP(src);
  if(!mac.isEmpty()&&macBlocked(mac)){
    int q=12;while(q<n&&buf[q]!=0){q+=buf[q]+1;}
    q+=5;if(q>n)return;
    static uint8_t resp[560];memcpy(resp,buf,q);
    resp[2]=0x81;resp[3]=0x80;resp[6]=0;resp[7]=1;
    int o=q;
    resp[o++]=0xC0;resp[o++]=0x0C;resp[o++]=0;resp[o++]=1;resp[o++]=0;resp[o++]=1;
    resp[o++]=0;resp[o++]=0;resp[o++]=0;resp[o++]=30;resp[o++]=0;resp[o++]=4;
    IPAddress ap=apIP();for(int i=0;i<4;i++)resp[o++]=ap[i];
    dnsUdp.beginPacket(src,sport);dnsUdp.write(resp,o);dnsUdp.endPacket();
    return;
  }
  IPAddress up1;
  if(cfg.dnsAuto){up1=WiFi.dnsIP();if((uint32_t)up1==0)up1.fromString(cfg.dns);}
  else up1.fromString(cfg.dns);
  if((uint32_t)up1==0)return;
  for(int i=0;i<6;i++)if(!dnsPend[i].used){
    dnsPend[i].used=true;dnsPend[i].id=((uint16_t)buf[0]<<8)|buf[1];
    dnsPend[i].src=src;dnsPend[i].port=sport;dnsPend[i].t=millis();
    dnsUp.beginPacket(up1,53);dnsUp.write(buf,n);dnsUp.endPacket();
    return;
  }
}
static void syncCaptive(){
  static bool last=false;
  const bool want=captiveActive();
  if(want==last&&captiveOn==want)return;
  last=want;
  if(want&&!captiveOn){dnsCaptive.start(53,"*",apIP());captiveOn=true;
    Serial.println("[WAV32] Portal cautivo activo (primer uso)");}
  if(!want&&captiveOn){dnsCaptive.stop();captiveOn=false;}
  applyApDns();
}
static void applyTxPower(){
  static const wifi_power_t T[]={WIFI_POWER_19_5dBm,WIFI_POWER_17dBm,
    WIFI_POWER_13dBm,WIFI_POWER_8_5dBm,WIFI_POWER_2dBm};
  WiFi.setTxPower(T[cfg.txPowerIdx<=4?cfg.txPowerIdx:0]);
}
static void onNetworkEvent(arduino_event_id_t event,arduino_event_info_t info) {
  (void)info;
  switch(event){
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      staHasIp=true;
      staIpNow=WiFi.localIP();staMaskNow=WiFi.subnetMask();
      staGwNow=WiFi.gatewayIP();staDnsNow=WiFi.dnsIP();
      upnetActive=upnetTry;staDropSince=0;wdFails=0;
      applyApDns();
      activateNat("STA_GOT_IP");
      break;
    case ARDUINO_EVENT_WIFI_STA_LOST_IP:
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      staHasIp=false;
      if(!staDropSince)staDropSince=millis();
      // 0.3.2: NAPT no se apaga al desconectar (patron 0.1.1: se enciende
      // una vez y no se toca; GOT_IP y pollUplink solo lo reactivan).
      break;
    case ARDUINO_EVENT_WIFI_AP_START:
      // El AP puede reiniciar (p. ej. al seguir el canal de la STA o tras un
      // escaneo) y ese ciclo tira NAPT: reactivarlo si ya hay uplink.
      if(staHasIp)activateNat("AP_START");
      break;
    default:break;
  }
}
static void connectUpstream() {
  if(upnetCount==0)return;
  if(upnetTry<0||upnetTry>=upnetCount)upnetTry=0;
  cfg.upstreamSsid=upnets[upnetTry].ssid;
  cfg.upstreamPassword=upnets[upnetTry].open?String(""):upnets[upnetTry].pass;
  WiFi.setAutoReconnect(true);
  if(cfg.wanStatic && validIPv4(cfg.wanIP) &&
     validIPv4(cfg.wanGateway) && validIPv4(cfg.wanMask)){
    IPAddress ip,gw,mask,dns1,dns2;
    ip.fromString(cfg.wanIP);gw.fromString(cfg.wanGateway);
    mask.fromString(cfg.wanMask);dns1.fromString(cfg.dns);
    if(!dns2.fromString(cfg.wanDNS2))dns2=IPAddress(8,8,8,8);
    WiFi.config(ip,gw,mask,dns1,dns2);
  } else {
    // DHCP: en el core 3.3.12, WiFi.config(INADDR_NONE,...) NO vuelve a DHCP:
    // INADDR_NONE es 255.255.255.255 y NetworkInterface lo trata como IP
    // estatica valida, apaga el cliente DHCP y la STA se queda sin IP real
    // de uplink (sin gateway ni DNS utiles): nadie navega. La forma correcta
    // de pedir DHCP en este core es configurar 0.0.0.0 (config() sin IP).
    WiFi.config(IPAddress(0,0,0,0),IPAddress(0,0,0,0),IPAddress(0,0,0,0));
  }
  Serial.printf("[WAV32] Buscando enlace WiFi %d/%d: %s\n",
                upnetTry+1,upnetCount,cfg.upstreamSsid.c_str());
  WiFi.begin(cfg.upstreamSsid.c_str(),cfg.upstreamPassword.c_str());
  lastReconnect=millis();
}
static void startNetwork() {
  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);
  WiFi.setHostname("wav32");
  IPAddress dns=effectiveDns();
  if(captiveActive())dns=apIP();
  // En primer uso el portal cautivo necesita que el DNS apunte a la propia AP;
  // despues, DHCP entrega el DNS efectivo (automatico del uplink o elegido).
  if(!WiFi.softAPConfig(apIP(),apIP(),apMask(),dhcpStart(),dns))
    Serial.println("[ERR] No se pudo configurar la LAN.");
  // NULL expresa WIFI_AUTH_OPEN (sin clave); la protección WPA2 es opcional.
  if(!WiFi.softAP(cfg.apSsid.c_str(),
                  cfg.apProtected?cfg.apPassword.c_str():nullptr,
                  cfg.channel,cfg.apHidden?1:0,cfg.maxClients))
    Serial.println("[ERR] No se pudo iniciar el punto de acceso.");
  // Provisional: la activacion que cuenta ocurre en STA_GOT_IP (activateNat),
  // porque sin IP de uplink el NAT no traduce y un ciclo del AP lo tira.
  natActive=WiFi.AP.enableNAPT(true);
  Serial.printf("[WAV32] AP: %s / %s / NAT inicial: %s\n",
                cfg.apSsid.c_str(),WiFi.softAPIP().toString().c_str(),
                natActive?"ON":"ERROR");
  applyTxPower();
  connectUpstream();
  configTime(cfg.utcOffsetMinutes*60,0,"pool.ntp.org","time.cloudflare.com");
}
static bool fromLAN(){ return server.client().localIP()==WiFi.softAPIP(); }
static bool fromWAN(){ return staHasIp && server.client().localIP()==WiFi.localIP(); }
static String requesterMac(){
  if(!fromLAN())return "";
  wifi_sta_list_t sta={};wifi_sta_mac_ip_list_t ips={};
  if(esp_wifi_ap_get_sta_list(&sta)==ESP_OK &&
     esp_wifi_ap_get_sta_list_with_ip(&sta,&ips)==ESP_OK)
    for(int i=0;i<ips.num;i++)
      if(IPAddress(ips.sta[i].ip.addr)==server.client().remoteIP())
        return formatMAC(ips.sta[i].mac);
  return "";
}
static bool connectedToLAN() {
  if(fromLAN()){
    // Con el modo invitado activo, el panel solo responde al equipo del dueño.
    if(cfg.guestMode && !cfg.ownerMac.isEmpty()){
      String m=requesterMac();
      if(!m.isEmpty() && m!=cfg.ownerMac)return false;
    }
    return true;
  }
  // Desde la red superior solo si el dueño lo activó (panel por esp.local);
  // por omisión la administración sigue cerrada hacia WAN.
  return cfg.wanAdmin && fromWAN();
}
static String makeToken(){
  String t="";char b[3];
  for(int i=0;i<16;i++){snprintf(b,sizeof b,"%02x",(unsigned)(esp_random()&0xFF));t+=b;}
  return t;
}
static bool sessionOK(){
  if(sessionToken.isEmpty())return false;
  return server.header("Cookie").indexOf("WAV32SID="+sessionToken)>=0;
}
static bool credentialsOK(){
  if(sessionOK())return true;
  String authorization=server.header("Authorization");
  if(!authorization.startsWith("Basic "))return false;
  String in=authorization.substring(6);
  unsigned char decoded[160]={0};size_t len=0;
  int ret=mbedtls_base64_decode(decoded,sizeof(decoded)-1,&len,
                               (const unsigned char*)in.c_str(),in.length());
  if(ret!=0||len>150)return false;
  decoded[len]='\0';String pair=(char*)decoded;
  int sep=pair.indexOf(':');
  return sep==5&&pair.substring(0,sep)=="admin"&&adminPasswordOK(pair.substring(sep+1));
}
static bool authOK() {
  if(!connectedToLAN()){
    server.send(403,"application/json","{\"error\":\"Solo se administra desde Wav32\"}");
    return false;
  }
  if(!cfg.adminClaimed){
    server.send(403,"application/json","{\"error\":\"Configura primero la clave admin en la pagina inicial\"}");
    return false;
  }
  if(!credentialsOK()){
    // Sin WWW-Authenticate: nada de dialogos del navegador; el panel
    // manda a su propia pagina de acceso.
    server.send(401,"application/json","{\"error\":\"Inicia sesion\"}");
    return false;
  }
  return true;
}
static void apiError(int status,const String& detail){
  StaticJsonDocument<230> d;d["error"]=detail;
  String body;serializeJson(d,body);server.send(status,"application/json; charset=utf-8",body);
}
static bool writeOK() {
  if(!authOK())return false;
  // Evita peticiones simples cross-site; los navegadores no permiten agregar
  // esta cabecera personalizada desde formularios de terceros.
  if(server.header("X-Wav32")!="1"){
    apiError(403,"Peticion sin proteccion de origen");return false;
  }
  return true;
}
static bool bodyJSON(DynamicJsonDocument& d){
  if(!server.hasArg("plain")||server.arg("plain").length()>3500){
    apiError(413,"JSON vacío o demasiado grande");return false;
  }
  if(deserializeJson(d,server.arg("plain"))){apiError(400,"JSON no válido");return false;}
  return true;
}
static void sendJSON(const JsonDocument& d,int status=200) {
  String out;serializeJson(d,out);
  server.sendHeader("Cache-Control","no-store");
  server.send(status,"application/json; charset=utf-8",out);
}
static void okReboot() {
  StaticJsonDocument<100>d;d["saved"]=true;d["restart"]=true;sendJSON(d);
  rebootAt=millis()+1800;
}
static void saveWAN(const JsonDocument& d){
  prefs.putString("stassid",cfg.upstreamSsid);
  prefs.putString("stapass",cfg.upstreamPassword);
  prefs.putBool("wanstat",cfg.wanStatic);
  prefs.putString("wanip",cfg.wanIP);
  prefs.putString("wangw",cfg.wanGateway);
  prefs.putString("wanmask",cfg.wanMask);
  prefs.putString("dns",cfg.dns);
  prefs.putString("dns2",cfg.wanDNS2);
  prefs.putBool("dnsauto",cfg.dnsAuto);
}
static void addStatus(JsonObject o){
  const bool online=WiFi.status()==WL_CONNECTED;
  o["firmware"]=FW_VERSION;o["uptimeSec"]=millis()/1000;
  o["apSsid"]=cfg.apSsid;o["apIP"]=WiFi.softAPIP().toString();
  o["apProtected"]=cfg.apProtected;
  o["clients"]=WiFi.softAPgetStationNum();o["maxClients"]=cfg.maxClients;
  o["upstreamSsid"]=cfg.upstreamSsid;o["connected"]=online;
  o["wanIP"]=online?WiFi.localIP().toString():"";
  o["gateway"]=online?WiFi.gatewayIP().toString():"";
  o["dns"]=online?WiFi.dnsIP().toString():cfg.dns;
  o["rssi"]=online?WiFi.RSSI():0;o["channel"]=WiFi.channel();
  o["nat"]=natActive;o["freeHeap"]=ESP.getFreeHeap();
  o["freePsram"]=ESP.getFreePsram();o["cpuMhz"]=ESP.getCpuFreqMHz();
  o["wanType"]=cfg.wanStatic?"static":"dhcp";
  o["dnsEffective"]=effectiveDns().toString();
  o["mdns"]="esp.local";
  o["isoUpstream"]=cfg.isoUpstream;o["isoClients"]=cfg.isoClients;
  o["guestMode"]=cfg.guestMode;o["wanAdmin"]=cfg.wanAdmin;
  o["dropUp"]=dropUpCount;o["dropCli"]=dropCliCount;
  o["upnetActive"]=upnetActive;o["upnetCount"]=upnetCount;
  o["watchdog"]=cfg.watchdog;o["wdFails"]=wdFails;
  o["tempC"]=temperatureRead();o["blockedCount"]=blockedCount();
  o["warning"]=configWarning;
  o["apMac"]=WiFi.softAPmacAddress();o["wanMac"]=WiFi.macAddress();
  if(online && WiFi.localIP()[0]==192 && WiFi.localIP()[1]==168 &&
      WiFi.localIP()[2]==cfg.lanOctet)
    o["warning"]="Conflicto de subred: cambia LAN a un tercer octeto distinto del WAN";
}
static void routeStatus(){
  if(!authOK())return;
  DynamicJsonDocument d(1900);JsonObject o=d.to<JsonObject>();
  addStatus(o);sendJSON(d);
}
static void routeConfig(){
  if(!authOK())return;
  DynamicJsonDocument d(3600);
  d["apSsid"]=cfg.apSsid;d["apPasswordSet"]=cfg.apProtected;
  d["apProtected"]=cfg.apProtected;
  d["upstreamSsid"]=cfg.upstreamSsid;
  d["upstreamPasswordSet"]=!cfg.upstreamPassword.isEmpty();
  d["lanOctet"]=cfg.lanOctet;d["channel"]=cfg.channel;
  d["maxClients"]=cfg.maxClients;d["apHidden"]=cfg.apHidden;
  d["dns"]=cfg.dns;d["wanStatic"]=cfg.wanStatic;
  d["wanIP"]=cfg.wanIP;d["wanGateway"]=cfg.wanGateway;
  d["wanMask"]=cfg.wanMask;d["wanDNS2"]=cfg.wanDNS2;
  d["ledEnabled"]=cfg.ledEnabled;d["ledOn"]=ledOn;
  d["dailyReboot"]=cfg.dailyReboot;d["rebootHour"]=cfg.rebootHour;
  d["rebootMinute"]=cfg.rebootMinute;d["utcOffsetMinutes"]=cfg.utcOffsetMinutes;
  d["macMode"]=cfg.macMode;d["macList"]=cfg.macList;
  d["blockedList"]=cfg.blockedList;d["blkMsg"]=cfg.blkMsg;
  d["firmware"]=FW_VERSION;
  JsonArray nets=d.createNestedArray("networks");
  for(int i=0;i<upnetCount;i++){
    JsonObject n=nets.createNestedObject();
    n["ssid"]=upnets[i].ssid;n["passwordSet"]=!upnets[i].pass.isEmpty();
    n["open"]=upnets[i].open;
  }
  d["dnsAuto"]=cfg.dnsAuto;d["wanAdmin"]=cfg.wanAdmin;
  d["isoUpstream"]=cfg.isoUpstream;d["isoClients"]=cfg.isoClients;
  d["guestMode"]=cfg.guestMode;d["watchdog"]=cfg.watchdog;
  d["txPower"]=cfg.txPowerIdx;d["ownerMacSet"]=!cfg.ownerMac.isEmpty();
  sendJSON(d);
}
static void routeClients() {
  if(!authOK())return;
  DynamicJsonDocument d(2100);JsonArray arr=d.createNestedArray("clients");
  wifi_sta_list_t list={};wifi_sta_mac_ip_list_t ips={};
  if(esp_wifi_ap_get_sta_list(&list)==ESP_OK && esp_wifi_ap_get_sta_list_with_ip(&list,&ips)==ESP_OK){
    for(int i=0;i<ips.num && i<8;i++){
      JsonObject x=arr.createNestedObject();
      x["mac"]=formatMAC(ips.sta[i].mac);
      IPAddress ip(ips.sta[i].ip.addr);
      x["ip"]=ip.toString();
      x["rssi"]=list.sta[i].rssi;
    }
  }
  sendJSON(d);
}
static void routeScan(){
  if(!authOK())return;
  // Escanear consume temporalmente tiempo de radio; nunca registra contraseñas.
  int count=WiFi.scanNetworks(false,true);
  DynamicJsonDocument d(4600);JsonArray out=d.createNestedArray("networks");
  for(int i=0;i<count&&i<22;i++){
    String s=WiFi.SSID(i);if(s.isEmpty())continue;
    JsonObject o=out.createNestedObject();
    o["ssid"]=s;o["rssi"]=WiFi.RSSI(i);
    o["secure"]=WiFi.encryptionType(i)!=WIFI_AUTH_OPEN;
    o["channel"]=WiFi.channel(i);
  }
  WiFi.scanDelete();sendJSON(d);
}
static void routeWireless(){
  if(!writeOK())return;
  DynamicJsonDocument d(900);if(!bodyJSON(d))return;
  String ap=d["ssid"]|String("");String pass=d["password"]|String("");
  int channel=d["channel"]|6,clients=d["clients"]|5;
  if(!validSSID(ap)||(!pass.isEmpty()&&!validPass(pass))||
     channel<1||channel>11||clients<1||clients>8){
    apiError(400,"SSID, clave, canal o límite de clientes inválido");return;
  }
  bool protectedAP=d["protected"]|false;
  if(protectedAP && pass.isEmpty() && !validPass(cfg.apPassword)){
    apiError(400,"Escribe una contraseña WPA2 de 8 a 63 caracteres");return;
  }
  cfg.apSsid=ap;cfg.apProtected=protectedAP;
  if(cfg.apProtected){
    if(!pass.isEmpty())cfg.apPassword=pass;
    prefs.putString("appass",cfg.apPassword);
  } else {
    cfg.apPassword="";
    prefs.remove("appass");
  }
  cfg.channel=channel;cfg.maxClients=clients;cfg.apHidden=d["hidden"]|false;
  prefs.putString("apssid",cfg.apSsid);prefs.putBool("approtect",cfg.apProtected);
  prefs.putUChar("channel",cfg.channel);prefs.putUChar("maxclient",cfg.maxClients);
  prefs.putBool("hidden",cfg.apHidden);
  int txp=d["txPower"]|(int)cfg.txPowerIdx;
  if(txp>=0&&txp<=4){cfg.txPowerIdx=(uint8_t)txp;prefs.putUChar("txpow",cfg.txPowerIdx);}
  okReboot();
}
static void routeWAN(){
  if(!writeOK())return;
  DynamicJsonDocument d(2400);if(!bodyJSON(d))return;
  // Hasta 3 redes superiores; se prueban en orden (failover automatico).
  UpNet nn[3];uint8_t nc=0;
  if(d["networks"].is<JsonArray>()){
    for(JsonObject o:d["networks"].as<JsonArray>()){
      if(nc>=3)break;
      String ss=o["ssid"]|String("");String pw=o["password"]|String("");
      bool op=o["open"]|false;bool keep=o["keep"]|false;
      if(ss.isEmpty())continue;
      if(!validSSID(ss)||pw.length()>63){
        apiError(400,"SSID o contraseña de red superior inválidos");return;
      }
      if(keep){
        for(int i=0;i<upnetCount;i++)
          if(upnets[i].ssid==ss){pw=upnets[i].pass;op=upnets[i].open;break;}
      }
      if(pw.isEmpty()&&!op){
        apiError(400,"Escribe la clave de cada red o márcala como abierta");return;
      }
      nn[nc].ssid=ss;nn[nc].pass=op?String(""):pw;nn[nc].open=op;nc++;
    }
  } else {
    String ss=d["ssid"]|String("");String pw=d["password"]|String("");
    bool op=d["open"]|false;
    if(!ss.isEmpty()){
      if(!validSSID(ss)||pw.length()>63){
        apiError(400,"SSID o contraseña inválidos");return;
      }
      if(pw.isEmpty()&&!op&&ss!=cfg.upstreamSsid){
        apiError(400,"Escribe la clave de la nueva red o marca que es abierta");return;
      }
      if(pw.isEmpty()&&!op)pw=cfg.upstreamPassword;
      nn[0].ssid=ss;nn[0].pass=op?String(""):pw;nn[0].open=op;nc=1;
    }
  }
  String dns=d["dns"]|String("1.1.1.1");
  bool dnsAuto=d["dnsAuto"]|cfg.dnsAuto;
  bool stat=d["static"]|false;
  String ip=d["ip"]|String(""),gw=d["gateway"]|String(""),
         mask=d["mask"]|String(""),dns2=d["dns2"]|String("");
  if(!validIPv4(dns)||(!dns2.isEmpty()&&!validIPv4(dns2))){
    apiError(400,"DNS inválido");return;
  }
  if(stat && (!validIPv4(ip)||!validIPv4(gw)||!validIPv4(mask))){
    apiError(400,"WAN fija necesita IP, gateway y máscara válidos");return;
  }
  if(stat){
    IPAddress n;n.fromString(ip);
    if(n[0]==192 && n[1]==168 && n[2]==cfg.lanOctet){
      apiError(400,"WAN y LAN no pueden compartir la misma subred");return;
    }
  }
  for(int i=0;i<nc;i++)upnets[i]=nn[i];
  upnetCount=nc;upnetTry=0;upnetActive=-1;
  cfg.wanStatic=stat;cfg.wanIP=ip;cfg.wanGateway=gw;cfg.wanMask=mask;
  cfg.dns=dns;cfg.wanDNS2=dns2;cfg.dnsAuto=dnsAuto;
  saveWAN(d);saveUpnets();okReboot();
}
static void routeLAN(){
  if(!writeOK())return;
  DynamicJsonDocument d(480);if(!bodyJSON(d))return;
  int octet=d["octet"]|0;
  if(octet<2||octet>250){apiError(400,"LAN debe ser 192.168.X.1, X entre 2 y 250");return;}
  cfg.lanOctet=octet;prefs.putUChar("lanoct",cfg.lanOctet);okReboot();
}
static void routeAccess(){
  if(!writeOK())return;
  DynamicJsonDocument d(900);if(!bodyJSON(d))return;
  String mode=d["mode"]|String("off");
  String list=d["list"]|String("");
  if(mode!="off"&&mode!="allow"&&mode!="deny"){
    apiError(400,"Modo de filtrado inválido");return;
  }
  String fixed;list.replace("\r","\n");list.replace(",","\n");
  int start=0;while(start<(int)list.length()){
    int end=list.indexOf('\n',start);if(end<0)end=list.length();
    String mac=list.substring(start,end);mac.trim();
    if(!mac.isEmpty()){if(!fixed.isEmpty())fixed+="\n";fixed+=normalizeMAC(mac);}
    start=end+1;
  }
  if(!validMACList(fixed)){apiError(400,"Usa máximo 16 MAC en formato AA:BB:CC:DD:EE:FF");return;}
  if(mode=="allow" && fixed.isEmpty()){
    apiError(400,"Añade al menos una MAC a la lista blanca; de lo contrario bloquearías todo acceso");return;
  }
  // Evita expulsar al administrador que está configurando la lista blanca.
  if(mode=="allow"){
    wifi_sta_list_t sta={};wifi_sta_mac_ip_list_t ips={};
    bool adminAllowed=false;
    if(esp_wifi_ap_get_sta_list(&sta)==ESP_OK &&
       esp_wifi_ap_get_sta_list_with_ip(&sta,&ips)==ESP_OK){
      for(int i=0;i<ips.num;i++){
        if(IPAddress(ips.sta[i].ip.addr)==server.client().remoteIP() &&
           (String("\n")+fixed+"\n").indexOf("\n"+formatMAC(ips.sta[i].mac)+"\n")>=0){
          adminAllowed=true;break;
        }
      }
    }
    if(!adminAllowed){
      apiError(400,"Tu propia MAC no figura en la lista blanca. Añádela antes de guardar");return;
    }
  }
  cfg.macMode=mode;cfg.macList=fixed;
  prefs.putString("macmode",cfg.macMode);prefs.putString("maclist",cfg.macList);
  StaticJsonDocument<90> ok;ok["saved"]=true;sendJSON(ok);
}
static void routeTime(){
  if(!writeOK())return;
  DynamicJsonDocument d(400);if(!bodyJSON(d))return;
  int hour=d["hour"]|4,minute=d["minute"]|0,offset=d["offset"]|-360;
  if(hour<0||hour>23||minute<0||minute>59||offset< -720||offset>840){
    apiError(400,"Hora o zona horaria inválida");return;
  }
  cfg.dailyReboot=d["enabled"]|false;
  cfg.rebootHour=hour;cfg.rebootMinute=minute;cfg.utcOffsetMinutes=offset;
  prefs.putBool("dreboot",cfg.dailyReboot);
  prefs.putUChar("rhour",cfg.rebootHour);
  prefs.putUChar("rmin",cfg.rebootMinute);
  prefs.putShort("tzoffset",cfg.utcOffsetMinutes);
  configTime(cfg.utcOffsetMinutes*60,0,"pool.ntp.org","time.cloudflare.com");
  StaticJsonDocument<90> ok;ok["saved"]=true;sendJSON(ok);
}
static void routeLED(){
  if(!writeOK())return;
  DynamicJsonDocument d(180);if(!bodyJSON(d))return;
  cfg.ledEnabled=d["enabled"]|false;ledOn=cfg.ledEnabled;
  prefs.putBool("led",cfg.ledEnabled);
  digitalWrite(LED_PIN,ledOn?HIGH:LOW);
  StaticJsonDocument<90> ok;ok["saved"]=true;sendJSON(ok);
}
static void routePortmap(){
  if(!authOK())return;
  DynamicJsonDocument d(1300);JsonArray arr=d.createNestedArray("rules");
  for(size_t i=0;i<ruleCount;i++){
    JsonObject o=arr.createNestedObject();o["index"]=i;
    o["protocol"]=rules[i].tcp?"TCP":"UDP";
    o["external"]=rules[i].externalPort;
    o["ip"]=rules[i].dest.toString();
    o["internal"]=rules[i].internalPort;
  }
  sendJSON(d);
}
static void routePortChange(){
  if(!writeOK())return;
  DynamicJsonDocument d(480);if(!bodyJSON(d))return;
  String action=d["action"]|String("");
  if(action=="delete"){
    int idx=d["index"]| -1;
    if(idx<0||idx>=(int)ruleCount){apiError(400,"Regla inexistente");return;}
    if(WiFi.status()==WL_CONNECTED)
      ip_portmap_remove(rules[idx].tcp?IPPROTO_TCP:IPPROTO_UDP,rules[idx].externalPort);
    for(size_t i=idx+1;i<ruleCount;i++)rules[i-1]=rules[i];ruleCount--;
    saveRules();StaticJsonDocument<100> ok;ok["saved"]=true;sendJSON(ok);return;
  }
  String proto=d["protocol"]|String("TCP"), ip=d["ip"]|String("");
  int ext=d["external"]|0,in=d["internal"]|0;IPAddress dest;
  if(action!="add"||(proto!="TCP"&&proto!="UDP")||!dest.fromString(ip)||
     dest[0]!=192||dest[1]!=168||dest[2]!=cfg.lanOctet||dest[3]==0||dest[3]==1||
     dest[3]==255||ext<1||ext>65535||in<1||in>65535){
    apiError(400,"Regla inválida; destino debe pertenecer a LAN Wav32");return;
  }
  if(ruleCount>=8){apiError(409,"Límite de ocho reglas");return;}
  for(size_t i=0;i<ruleCount;i++)
    if(rules[i].tcp==(proto=="TCP")&&rules[i].externalPort==ext){
      apiError(409,"El puerto externo ya está asignado");return;
    }
  rules[ruleCount++]={proto=="TCP",(uint16_t)ext,dest,(uint16_t)in};
  saveRules();restoreMappings();
  StaticJsonDocument<90> ok;ok["saved"]=true;sendJSON(ok);
}
static void routeDNS(){
  if(!authOK())return;
  String host=server.arg("host");host.trim();
  if(host.length()<3||host.length()>100||host.indexOf('/')>=0||
     host.indexOf(' ')>=0){apiError(400,"Dominio inválido");return;}
  IPAddress ip;bool ok=WiFi.hostByName(host.c_str(),ip);
  StaticJsonDocument<170> d;d["host"]=host;d["resolved"]=ok;
  d["ip"]=ok?ip.toString():"";sendJSON(d);
}
static void routeIsolation(){
  if(!writeOK())return;
  DynamicJsonDocument d(300);if(!bodyJSON(d))return;
  cfg.isoUpstream=d["upstream"]|false;cfg.isoClients=d["clients"]|false;
  prefs.putBool("isoup",cfg.isoUpstream);prefs.putBool("isocli",cfg.isoClients);
  // El hook lwIP lee estas banderas en vivo: no hace falta reiniciar.
  StaticJsonDocument<90> ok;ok["saved"]=true;sendJSON(ok);
}
static void routeToggles(){
  if(!writeOK())return;
  DynamicJsonDocument d(300);if(!bodyJSON(d))return;
  cfg.wanAdmin=d["wanAdmin"]|cfg.wanAdmin;cfg.watchdog=d["watchdog"]|cfg.watchdog;
  prefs.putBool("wanadmin",cfg.wanAdmin);prefs.putBool("watchdog",cfg.watchdog);
  StaticJsonDocument<90> ok;ok["saved"]=true;sendJSON(ok);
}
static void routeGuest(){
  if(!writeOK())return;
  DynamicJsonDocument d(500);if(!bodyJSON(d))return;
  bool enable=d["enabled"]|false;
  String pass=d["password"]|String("");
  if(enable){
    String m=requesterMac();
    if(m.isEmpty()){
      apiError(400,"Conéctate a la red Wav32 para activar el modo invitado");return;
    }
    if(!pass.isEmpty()&&!validPass(pass)){
      apiError(400,"La clave temporal debe tener 8 a 63 caracteres");return;
    }
    if(!cfg.guestMode){
      cfg.guestPrevProtected=cfg.apProtected;cfg.guestPrevPass=cfg.apPassword;
      prefs.putBool("gprevprot",cfg.guestPrevProtected);
      if(cfg.guestPrevProtected)prefs.putString("gprevpass",cfg.guestPrevPass);
      else prefs.remove("gprevpass");
    }
    cfg.ownerMac=m;prefs.putString("ownermac",m);
    cfg.guestMode=true;prefs.putBool("guest",true);
    if(!pass.isEmpty()){
      cfg.apProtected=true;cfg.apPassword=pass;
      prefs.putBool("approtect",true);prefs.putString("appass",pass);
    }
  } else {
    cfg.guestMode=false;prefs.putBool("guest",false);
    cfg.apProtected=cfg.guestPrevProtected;
    cfg.apPassword=cfg.guestPrevProtected?cfg.guestPrevPass:String("");
    prefs.putBool("approtect",cfg.apProtected);
    if(cfg.apProtected)prefs.putString("appass",cfg.apPassword);
    else prefs.remove("appass");
  }
  okReboot();
}
static void routeRestore(){
  if(!writeOK())return;
  DynamicJsonDocument d(1600);if(!bodyJSON(d))return;
  if((d["version"]|String(""))!="Wav32-backup-v1"){
    apiError(400,"El archivo no es un respaldo Wav32 válido");return;
  }
  String ap=d["apSsid"]|String("");
  if(validSSID(ap)){cfg.apSsid=ap;prefs.putString("apssid",ap);}
  String up=d["upstreamSsid"]|String("");
  if(!up.isEmpty()&&validSSID(up)){
    bool known=false;
    for(int i=0;i<upnetCount;i++)if(upnets[i].ssid==up)known=true;
    if(!known){upnets[0].ssid=up;upnets[0].pass="";upnets[0].open=false;
      if(upnetCount==0)upnetCount=1;}
    saveUpnets();
  }
  int oc=d["lanOctet"]|0;if(oc>=2&&oc<=250){cfg.lanOctet=oc;prefs.putUChar("lanoct",oc);}
  int ch=d["channel"]|0;if(ch>=1&&ch<=11){cfg.channel=ch;prefs.putUChar("channel",ch);}
  int mc=d["maxClients"]|0;if(mc>=1&&mc<=8){cfg.maxClients=mc;prefs.putUChar("maxclient",mc);}
  cfg.apHidden=d["hidden"]|cfg.apHidden;prefs.putBool("hidden",cfg.apHidden);
  String dn=d["dns"]|String("");
  if(validIPv4(dn)){cfg.dns=dn;prefs.putString("dns",dn);}
  cfg.dnsAuto=d["dnsAuto"]|cfg.dnsAuto;prefs.putBool("dnsauto",cfg.dnsAuto);
  String mm=d["macMode"]|String("");
  if(mm=="off"||mm=="allow"||mm=="deny"){
    String ml=d["macList"]|String("");
    if(validMACList(ml)){cfg.macMode=mm;cfg.macList=ml;
      prefs.putString("macmode",mm);prefs.putString("maclist",ml);}
    String bl=d["blockedList"]|String("");
    if(validMACList(bl)){cfg.blockedList=bl;prefs.putString("blklist",bl);}
    String bm=d["blkMsg"]|String("");
    if(!bm.isEmpty()&&bm.length()<=240){cfg.blkMsg=bm;prefs.putString("blkmsg",bm);}
  }
  cfg.dailyReboot=d["dailyReboot"]|cfg.dailyReboot;
  cfg.rebootHour=d["rebootHour"]|cfg.rebootHour;
  cfg.rebootMinute=d["rebootMinute"]|cfg.rebootMinute;
  prefs.putBool("dreboot",cfg.dailyReboot);
  prefs.putUChar("rhour",cfg.rebootHour);prefs.putUChar("rmin",cfg.rebootMinute);
  cfg.isoUpstream=d["isoUpstream"]|cfg.isoUpstream;
  cfg.isoClients=d["isoClients"]|cfg.isoClients;
  prefs.putBool("isoup",cfg.isoUpstream);prefs.putBool("isocli",cfg.isoClients);
  int tx=d["txPower"]|(int)cfg.txPowerIdx;
  if(tx>=0&&tx<=4){cfg.txPowerIdx=(uint8_t)tx;prefs.putUChar("txpow",cfg.txPowerIdx);}
  okReboot();
}
static bool otaBad=false;
static void routeOtaUpload(){
  HTTPUpload& up=server.upload();
  if(up.status==UPLOAD_FILE_START){
    otaBad=false;
    if(!authOK()){otaBad=true;return;}
    if(!up.filename.endsWith(".bin")){otaBad=true;return;}
    if(!Update.begin(UPDATE_SIZE_UNKNOWN,U_FLASH))otaBad=true;
  } else if(up.status==UPLOAD_FILE_WRITE){
    if(!otaBad&&(int)Update.write(up.buf,up.currentSize)!=(int)up.currentSize)
      otaBad=true;
  } else if(up.status==UPLOAD_FILE_END){
    if(!otaBad&&!Update.end(true))otaBad=true;
  } else if(up.status==UPLOAD_FILE_ABORTED){
    Update.abort();
  }
}
static void routeOtaDone(){
  if(otaBad||Update.hasError()){
    Update.printError(Serial);
    apiError(400,"Archivo de firmware no válido");return;
  }
  okReboot();
}
static void routeBackup(){
  if(!authOK())return;
  DynamicJsonDocument d(1100);
  // NUNCA incluir contraseñas Wi-Fi ni el hash del administrador.
  d["version"]="Wav32-backup-v1";d["apSsid"]=cfg.apSsid;
  d["upstreamSsid"]=cfg.upstreamSsid;
  d["lanOctet"]=cfg.lanOctet;d["channel"]=cfg.channel;
  d["maxClients"]=cfg.maxClients;d["hidden"]=cfg.apHidden;
  d["dns"]=cfg.dns;d["macMode"]=cfg.macMode;d["macList"]=cfg.macList;
    d["blockedList"]=cfg.blockedList;d["blkMsg"]=cfg.blkMsg;
  d["dailyReboot"]=cfg.dailyReboot;
  d["rebootHour"]=cfg.rebootHour;d["rebootMinute"]=cfg.rebootMinute;
  d["dnsAuto"]=cfg.dnsAuto;d["isoUpstream"]=cfg.isoUpstream;
  d["isoClients"]=cfg.isoClients;d["txPower"]=cfg.txPowerIdx;
  d["utcOffsetMinutes"]=cfg.utcOffsetMinutes;
  String payload;serializeJsonPretty(d,payload);
  server.sendHeader("Content-Disposition","attachment; filename=\"Wav32-backup.json\"");
  server.sendHeader("Cache-Control","no-store");
  server.send(200,"application/json; charset=utf-8",payload);
}
static void routePassword(){
  if(!writeOK())return;
  DynamicJsonDocument d(500);if(!bodyJSON(d))return;
  String old=d["old"]|String(""),pass=d["password"]|String("");
  if(!adminPasswordOK(old)||pass.length()<4||pass.length()>64){
    apiError(400,"Clave actual incorrecta o nueva clave fuera de 4–64 caracteres");return;
  }
  updateAdmin(pass);cfg.adminClaimed=true;prefs.putBool("admClaim",true);
  StaticJsonDocument<100>ok;ok["saved"]=true;sendJSON(ok);
}
static void routeReboot(){
  if(!writeOK())return;
  StaticJsonDocument<100>ok;ok["restart"]=true;sendJSON(ok);
  rebootAt=millis()+1000;
}
static void routeFactory(){
  if(!writeOK())return;
  DynamicJsonDocument d(200);if(!bodyJSON(d))return;
  if(d["confirm"]!=String("RESTABLECER")){apiError(400,"Confirmación incorrecta");return;}
  prefs.clear();okReboot();
}
static const char FIRST_SETUP[] PROGMEM=R"WR32(<!doctype html>
<html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#173454"><title>Wav32 · Primer acceso</title>
<style>body{font:16px/1.5 system-ui,Arial,sans-serif;background:#eff4f8;color:#173454;display:grid;place-items:center;min-height:90vh;padding:15px}.card{background:#fff;padding:30px;max-width:440px;width:100%;border-radius:14px;box-shadow:0 7px 30px #14375818}h1{margin:0 0 5px}small{color:#687f90}label{display:block;margin:17px 0 5px;font-weight:650}input{box-sizing:border-box;width:100%;font-size:16px;padding:12px;border:1px solid #c9d8e4;border-radius:7px}button{margin-top:20px;width:100%;padding:13px;border:0;background:#1682c6;color:white;border-radius:7px;font-weight:700}p{font-size:14px}#msg{color:#b63443}</style>
<main class="card"><h1>Wav32</h1><small>Configuración inicial · Wi-Fi abierto</small>
<p>Conectaste a Wav32 sin contraseña Wi-Fi. Antes de usar el panel, crea una contraseña de administrador. <strong>Cualquier equipo cercano puede acceder a esta red abierta hasta que actives WPA2.</strong></p>
<form id="f"><label>Clave nueva de administrador (mínimo 4 caracteres)</label>
<input id="a" type="password" minlength="12" maxlength="64" autocomplete="new-password" required>
<label>Repetir clave</label><input id="b" type="password" minlength="12" maxlength="64" autocomplete="new-password" required>
<button>Crear administrador</button></form><p id="msg" role="status"></p></main>
<script>document.getElementById('f').addEventListener('submit',async e=>{
e.preventDefault();const a=document.getElementById('a').value,b=document.getElementById('b').value,m=document.getElementById('msg');
if(a!==b){m.textContent='Las claves no coinciden';return;}
try{const r=await fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json','X-Wav32':'1'},body:JSON.stringify({password:a})});const v=await r.json();if(!r.ok)throw Error(v.error||'Error');
m.textContent='Administrador creado. Entrando al panel…';setTimeout(()=>location.reload(),1300);
}catch(x){m.textContent=x.message;}});</script></html>)WR32";
static void routeInitialSetup(){
  if(cfg.adminClaimed){apiError(409,"Administrador ya configurado");return;}
  if(!connectedToLAN()){apiError(403,"Solo desde la red local Wav32");return;}
  if(server.header("X-Wav32")!="1"){apiError(403,"Solicitud inválida");return;}
  DynamicJsonDocument d(250);if(!bodyJSON(d))return;
  String password=d["password"]|String("");
  if(password.length()<4||password.length()>64){
    apiError(400,"Elige una clave de 4 a 64 caracteres");return;
  }
  updateAdmin(password);
  cfg.adminClaimed=true;
  prefs.putBool("admClaim",true);
  String owner=requesterMac();
  if(!owner.isEmpty()){cfg.ownerMac=owner;prefs.putString("ownermac",owner);}
  sessionToken=makeToken();prefs.putString("sid",sessionToken);
  server.sendHeader("Set-Cookie","WAV32SID="+sessionToken+"; Path=/; HttpOnly; SameSite=Strict");
  syncCaptive();
  StaticJsonDocument<110> result;result["configured"]=true;sendJSON(result);
}

static const char BLOCKED_HTML[] PROGMEM=R"HTML(
<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Has sido bloqueado · Wav32</title><style>body{margin:0;font-family:system-ui,Arial,sans-serif;background:#0a0f1a;color:#e8eef7;display:grid;place-items:center;min-height:100vh;padding:18px}.card{background:#111a2b;border:1px solid #f8717155;border-radius:18px;max-width:430px;width:100%;padding:34px 28px;text-align:center;box-sizing:border-box}.ic{width:70px;height:70px;margin:0 auto 16px;border-radius:18px;background:#f8717118;display:grid;place-items:center;font-size:34px}h1{font-size:23px;margin:0 0 10px}p{color:#8fa3bd;line-height:1.6;font-size:14.5px}.m{color:#e8eef7}</style></head><body><div class="card"><div class="ic">&#128737;</div><h1>Has sido bloqueado</h1><p class="m">%MSG%</p><p>Estas conectado a la red <b>%SSID%</b>, pero este dispositivo no tiene acceso a internet.</p></div></body></html>
)HTML";
static void serveBlockedPage(){
  String msg=cfg.blkMsg;
  msg.replace("&","&amp;");msg.replace("<","&lt;");msg.replace(">","&gt;");
  String page=BLOCKED_HTML;
  page.replace("%MSG%",msg);
  page.replace("%SSID%",cfg.apSsid);
  server.sendHeader("Cache-Control","no-store");
  server.send(200,"text/html; charset=utf-8",page);
}
static bool requesterBlocked(){
  if(cfg.blockedList.isEmpty()||!fromLAN())return false;
  String m=requesterMac();
  return !m.isEmpty()&&macBlocked(m);
}
// La UI se sirve en streaming por bloques: con send_P de una sola pieza el
// payload grande (0.4.0) llegaba truncado a algunos navegadores.
static void serveGzip(const uint8_t* data,size_t len,const char* type,bool cache){
  server.sendHeader("Content-Encoding","gzip");
  server.sendHeader("Cache-Control",cache?"public, max-age=604800":"no-store");
  server.setContentLength(len);
  server.send(200,type,"");
  size_t off=0;
  while(off<len){
    const size_t chunk=(len-off)>4096?4096:(len-off);
    server.sendContent_P((const char*)(data+off),chunk);
    off+=chunk;
  }
}
static void routeChart(){
  if(!authOK())return;
  serveGzip(WAV32_CHART_GZIP,WAV32_CHART_GZIP_LEN,
            "application/javascript; charset=utf-8",true);
}
static const char LOGIN_HTML[] PROGMEM=R"HTML(
<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Acceso · Wav32</title><style>*{box-sizing:border-box}body{margin:0;font-family:system-ui,Arial,sans-serif;background:radial-gradient(1000px 500px at 50% -10%,#38bdf81c,transparent),#0a0f1a;color:#e8eef7;display:grid;place-items:center;min-height:100vh;padding:18px}.card{background:#111a2b;border:1px solid #263650;border-radius:20px;max-width:400px;width:100%;padding:34px 28px;text-align:center;box-shadow:0 24px 60px #0009}.ic{width:66px;height:66px;margin:0 auto 14px;border-radius:18px;background:#38bdf814;color:#38bdf8;display:grid;place-items:center;font-size:30px}h1{font-size:23px;margin:0}p{color:#8fa3bd;line-height:1.55;font-size:14px;margin:8px 0 0}input{width:100%;margin-top:20px;background:#0a0f1a;border:1px solid #263650;border-radius:11px;color:#e8eef7;padding:13px 14px;font-size:15px;font-family:inherit}input:focus{outline:2px solid #38bdf866;border-color:#38bdf8}button{width:100%;margin-top:12px;background:#0284c7;color:#fff;border:0;border-radius:11px;padding:13px;font-size:15px;font-weight:700;cursor:pointer;font-family:inherit}.err{color:#f87171;min-height:20px;font-size:13.5px;margin-top:10px}small{color:#5b6b82;font-size:12px}</style></head><body>
<form class="card" id="f"><div class="ic">&#128272;</div><h1>Wav32</h1><p>Panel de control<br>Escribe tu contraseña de administrador</p><input type="password" id="pw" placeholder="Contraseña" autocomplete="current-password" autofocus><div class="err" id="er"></div><button type="submit">Entrar</button><p><small>Red %SSID% · acceso protegido</small></p></form>
<script>
document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();
 const pw=document.getElementById('pw').value,er=document.getElementById('er');er.textContent='';
 try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-Wav32':'1'},body:JSON.stringify({password:pw})});
 const v=await r.json().catch(()=>({}));
 if(!r.ok)throw new Error(v.error||'Error de acceso');
 location.href='/';
 }catch(x){er.textContent=x.message;}});
</script></body></html>
)HTML";
static void serveLoginPage(){
  String page=LOGIN_HTML;
  page.replace("%SSID%",cfg.apSsid);
  server.sendHeader("Cache-Control","no-store");
  server.send(200,"text/html; charset=utf-8",page);
}
static void routeLogin(){
  if(!connectedToLAN()){apiError(403,"Solo desde las redes de Wav32");return;}
  if(!cfg.adminClaimed){apiError(403,"Configura primero la clave admin");return;}
  if(server.header("X-Wav32")!="1"){apiError(403,"Solicitud invalida");return;}
  if(loginLockUntil&&(int32_t)(loginLockUntil-millis())>0){
    apiError(429,"Demasiados intentos. Espera un minuto.");return;}
  DynamicJsonDocument d(300);if(!bodyJSON(d))return;
  String pw=d["password"]|String("");
  if(!adminPasswordOK(pw)){
    if(++loginFails>=5){loginLockUntil=millis()+60000;loginFails=0;}
    apiError(401,"Contraseña incorrecta");return;
  }
  loginFails=0;
  sessionToken=makeToken();prefs.putString("sid",sessionToken);
  server.sendHeader("Set-Cookie","WAV32SID="+sessionToken+"; Path=/; HttpOnly; SameSite=Strict");
  StaticJsonDocument<80> ok;ok["ok"]=true;sendJSON(ok);
}
static void routeLogout(){
  if(!authOK())return;
  sessionToken="";prefs.remove("sid");
  server.sendHeader("Set-Cookie","WAV32SID=; Path=/; Max-Age=0");
  StaticJsonDocument<80> ok;ok["ok"]=true;sendJSON(ok);
}
static void routeIndex(){
  if(!cfg.adminClaimed){
    if(!connectedToLAN()){apiError(403,"Solo desde la red local Wav32");return;}
    server.sendHeader("Cache-Control","no-store");
    server.send_P(200,"text/html; charset=utf-8",FIRST_SETUP);
    return;
  }
  if(requesterBlocked()){serveBlockedPage();return;}
  if(!credentialsOK()){
    if(!connectedToLAN()){apiError(403,"Solo desde la red local Wav32");return;}
    serveLoginPage();return;
  }
  serveGzip(WAV32_UI_GZIP,WAV32_UI_GZIP_LEN,"text/html; charset=utf-8",false);
}
static void routeBlock(){
  if(!writeOK())return;
  DynamicJsonDocument d(700);if(!bodyJSON(d))return;
  if(d["msg"].is<const char*>()){
    String m=d["msg"]|String("");
    m.trim();
    if(m.isEmpty()||m.length()>240){apiError(400,"Mensaje vacio o demasiado largo");return;}
    cfg.blkMsg=m;prefs.putString("blkmsg",m);
    StaticJsonDocument<90> ok;ok["saved"]=true;sendJSON(ok);return;
  }
  String mac=normalizeMAC(d["mac"]|String(""));
  String act=d["action"]|String("");
  uint8_t tmp[6];
  if(!parseMAC(mac,tmp)){apiError(400,"MAC invalida");return;}
  /* 0.4.5: sin candados: el dueno puede bloquear cualquier dispositivo,
     incluido el suyo o desde el que administra (sin excepciones). */
  const bool wasActive=blockedCount()>0;
  if(act=="add"){
    if(macBlocked(mac)){apiError(409,"Ese dispositivo ya esta bloqueado");return;}
    if(blockedCount()>=8){apiError(400,"Maximo 8 dispositivos bloqueados");return;}
    cfg.blockedList=cfg.blockedList.isEmpty()?mac:cfg.blockedList+"\n"+mac;
  }else if(act=="remove"){
    String out="";int start=0;
    while(start<(int)cfg.blockedList.length()){
      int nl=cfg.blockedList.indexOf('\n',start);
      String line=nl<0?cfg.blockedList.substring(start):cfg.blockedList.substring(start,nl);
      if(line!=mac){if(!out.isEmpty())out+="\n";out+=line;}
      if(nl<0)break;start=nl+1;
    }
    cfg.blockedList=out;
  }else{apiError(400,"Accion invalida");return;}
  prefs.putString("blklist",cfg.blockedList);
  applyApDns();syncDnsProxy();
  if(wasActive!=(blockedCount()>0)||act=="add")deauthMac(mac);
  StaticJsonDocument<90> ok;ok["saved"]=true;sendJSON(ok);
}
static void routeKick(){
  if(!writeOK())return;
  DynamicJsonDocument d(300);if(!bodyJSON(d))return;
  String mac=normalizeMAC(d["mac"]|String(""));
  uint8_t tmp[6];
  if(!parseMAC(mac,tmp)){apiError(400,"MAC invalida");return;}
  deauthMac(mac);
  StaticJsonDocument<90> ok;ok["saved"]=true;sendJSON(ok);
}
static void startPortal() {
  server.collectHeaders(HEADERS,3);
  server.on("/",HTTP_GET,routeIndex);
  server.on("/api/setup",HTTP_POST,routeInitialSetup);
  server.on("/api/block",HTTP_POST,routeBlock);
  server.on("/api/kick",HTTP_POST,routeKick);
  server.on("/chart.js",HTTP_GET,routeChart);
  server.on("/api/login",HTTP_POST,routeLogin);
  server.on("/api/logout",HTTP_POST,routeLogout);
  server.on("/api/status",HTTP_GET,routeStatus);
  server.on("/api/config",HTTP_GET,routeConfig);
  server.on("/api/clients",HTTP_GET,routeClients);
  server.on("/api/scan",HTTP_GET,routeScan);
  server.on("/api/portmaps",HTTP_GET,routePortmap);
  server.on("/api/dns",HTTP_GET,routeDNS);
  server.on("/api/backup",HTTP_GET,routeBackup);
  server.on("/api/wireless",HTTP_POST,routeWireless);
  server.on("/api/wan",HTTP_POST,routeWAN);
  server.on("/api/lan",HTTP_POST,routeLAN);
  server.on("/api/access",HTTP_POST,routeAccess);
  server.on("/api/schedule",HTTP_POST,routeTime);
  server.on("/api/led",HTTP_POST,routeLED);
  server.on("/api/portmaps",HTTP_POST,routePortChange);
  server.on("/api/admin",HTTP_POST,routePassword);
  server.on("/api/reboot",HTTP_POST,routeReboot);
  server.on("/api/factory",HTTP_POST,routeFactory);
  server.on("/api/isolation",HTTP_POST,routeIsolation);
  server.on("/api/toggles",HTTP_POST,routeToggles);
  server.on("/api/guest",HTTP_POST,routeGuest);
  server.on("/api/restore",HTTP_POST,routeRestore);
  server.on("/api/ota",HTTP_POST,routeOtaDone,routeOtaUpload);
  // Sondas de deteccion de portal (Android/iOS/Windows): en primer uso
  // redirigen al panel; con el router ya configurado responden normal.
  static const char* PROBES[]={"/generate_204","/gen_204","/hotspot-detect.html",
    "/connecttest.txt","/ncsi.txt","/redirect"};
  for(int i=0;i<6;i++)
    server.on(PROBES[i],HTTP_GET,[](){
      if(captiveActive()&&fromLAN()){
        server.sendHeader("Location","http://"+apIP().toString()+"/",true);
        server.send(302,"text/plain","");
      } else server.send(204,"text/plain","");
    });
  server.onNotFound([](){
    if(cfg.adminClaimed&&requesterBlocked()){
      serveBlockedPage();return;
    }
    if(captiveActive()&&fromLAN()&&!server.uri().startsWith("/api/")){
      server.sendHeader("Location","http://"+apIP().toString()+"/",true);
      server.send(302,"text/plain","");return;
    }
    apiError(404,"Ruta desconocida");
  });
  server.begin();
}
static void enforceAccess(){
  wifi_sta_list_t list={};
  if(esp_wifi_ap_get_sta_list(&list)!=ESP_OK)return;
  for(int i=0;i<list.num;i++){
    if(!macAllowed(formatMAC(list.sta[i].mac))){
      uint16_t aid=0;
      if(esp_wifi_ap_get_sta_aid(list.sta[i].mac,&aid)==ESP_OK && aid)
        esp_wifi_deauth_sta(aid);
    }
  }
}
static void pollUplink(){
  const uint32_t now=millis();
  if(upnetCount==0)return;
  if(WiFi.status()!=WL_CONNECTED){
    if(!staDropSince)staDropSince=now;
    if(now-lastReconnect>=RECONNECT_MS){WiFi.reconnect();lastReconnect=now;}
    // Failover: 60 s sin enlace en esta red -> probar la siguiente guardada.
    if(upnetCount>1 && staDropSince && now-staDropSince>60000){
      upnetTry=(upnetTry+1)%(int)upnetCount;staDropSince=now;lastReconnect=0;
      Serial.printf("[WAV32] Failover: probando red %d/%d\n",upnetTry+1,upnetCount);
      WiFi.disconnect();connectUpstream();
    }
  } else {
    staDropSince=0;lastReconnect=now;
    // Autorreparacion: si un ciclo del AP o de la STA tiro el NAT y el
    // evento se perdio, reactivarlo en cuanto se detecta sin NAT.
    if(!natActive)activateNat("poll");
  }
}
// Watchdog de internet real: ping ICMP alterno al gateway y a 1.1.1.1.
// Tres fallos seguidos -> reconectar; seis -> reiniciar. No bloquea el loop:
// la sesion esp_ping es asincrona y se recoge el resultado al terminar.
static void wdOnSuccess(esp_ping_handle_t hdl,void* args){
  (void)hdl;(void)args;wdPingOk=true;
}
static void wdOnEnd(esp_ping_handle_t hdl,void* args){
  (void)hdl;(void)args;wdPingDone=true;
}
static void pollWatchdog(){
  if(wdPingDone){
    wdPingDone=false;
    if(wdSession){esp_ping_delete_session(wdSession);wdSession=nullptr;}
    if(!staHasIp){wdGwDone=false;}
    else if(wdLastGw){wdGwOk=wdPingOk;wdGwDone=true;}
    else{
      // Ronda completa (gateway + 1.1.1.1): solo cuenta fallo si AMBOS
      // destinos callan. Muchos routers filtran ICMP aunque el internet
      // real funcione; la 0.3.0 desconectaba con 3 pings fallidos y
      // dejaba la red en cortes repetidos.
      const bool pairFail=wdGwDone&&!wdGwOk&&!wdPingOk;
      wdGwDone=false;
      if(!pairFail)wdFails=0;
      else{
        wdFails++;
        if(wdFails==6){
          Serial.println("[WAV32] Watchdog: 6 rondas sin respuesta; reconnect");
          WiFi.reconnect();
        }
        if(wdFails>=12){
          Serial.println("[WAV32] Watchdog: reinicio por falta de respuesta");
          rebootAt=millis()+1200;wdFails=0;
        }
      }
    }
  }
  if(!cfg.watchdog||!staHasIp||wdSession)return;
  const uint32_t now=millis();
  if(now-lastWatchdog<30000)return;
  lastWatchdog=now;wdCycle++;
  wdLastGw=(wdCycle%2==0&&(uint32_t)staGwNow!=0);
  IPAddress target=wdLastGw?staGwNow:IPAddress(1,1,1,1);
  esp_ping_config_t pc=ESP_PING_DEFAULT_CONFIG();
  pc.target_addr.type=IPADDR_TYPE_V4;
  pc.target_addr.u_addr.ip4.addr=(uint32_t)target;
  pc.count=1;pc.timeout_ms=1500;pc.interval_ms=100;
  pc.task_stack_size=3072;pc.task_prio=2;
  esp_ping_callbacks_t cb={};
  cb.cb_args=nullptr;cb.on_ping_success=wdOnSuccess;
  cb.on_ping_timeout=nullptr;cb.on_ping_end=wdOnEnd;
  wdPingOk=false;wdPingDone=false;
  if(esp_ping_new_session(&pc,&cb,&wdSession)==ESP_OK&&wdSession)
    esp_ping_start(wdSession);
  else wdSession=nullptr;
}
static void pollSchedule(){
  if(!cfg.dailyReboot)return;
  time_t now=time(nullptr);
  if(now<1700000000)return;
  struct tm local={};localtime_r(&now,&local);
  int day=local.tm_year*400+local.tm_yday;
  if(day!=lastRebootDay&&local.tm_hour==cfg.rebootHour&&
     local.tm_min==cfg.rebootMinute){
    lastRebootDay=day;
    prefs.putInt("lastrday",day); // evita bucle de reinicios durante el mismo minuto
    rebootAt=millis()+1500;
  }
}
void setup(){
  Serial.begin(115200);delay(200);
  Serial.println("\n=== Wav32 NAT Router ===");
  pinMode(LED_PIN,OUTPUT);digitalWrite(LED_PIN,LOW);
  // La radio Wi-Fi aporta entropía física al generador de credenciales.
  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);
  loadSettings();ledOn=cfg.ledEnabled;digitalWrite(LED_PIN,ledOn?HIGH:LOW);
  Network.onEvent(onNetworkEvent);
  startNetwork();
  if(MDNS.begin("esp")){
    MDNS.addService("http","tcp",80);
    Serial.println("[WAV32] Panel tambien en http://esp.local");
  }
  syncCaptive();
  startPortal();
  Serial.println("[WAV32] ADMINISTRACIÓN DESDE LA RED Wav32: http://"+WiFi.softAPIP().toString());
  Serial.println("[WAV32] Sin servicio en Dex, sin microSD, sin cámara");
}
void loop(){
  server.handleClient();
  if(captiveOn)dnsCaptive.processNextRequest();
  pollDnsProxy();
  if(Serial.available()){
    String x=Serial.readStringUntil('\n');x.trim();
    if(x=="help")Serial.println("Comandos USB: status, factory-reset (borra configuración)");
    if(x=="status"){
      Serial.printf("[WAV32] WiFi %s, STA %s, AP %s, NAT %d, free %u\n",
          cfg.upstreamSsid.c_str(),WiFi.localIP().toString().c_str(),
          WiFi.softAPIP().toString().c_str(),natActive,(unsigned)ESP.getFreeHeap());
    }
    if(x=="factory-reset"){
      Serial.println("[WAV32] Restableciendo configuración Wav32");
      prefs.clear();delay(250);ESP.restart();
    }
  }
  if(millis()-lastClientCheck>CLIENT_CHECK_MS){
    lastClientCheck=millis();enforceAccess();
  }
  if(millis()-lastStatus>STATUS_MS){
    lastStatus=millis();pollUplink();pollSchedule();pollWatchdog();syncCaptive();syncDnsProxy();
  }
  if(rebootAt && (int32_t)(millis()-rebootAt)>=0){
    Serial.println("[WAV32] Reiniciando...");delay(150);ESP.restart();
  }
  static uint32_t lastHb=0;
  if(millis()-lastHb>15000){
    lastHb=millis();
    Serial.printf("[WAV32] HB st=%d hasIp=%d NAT=%d cli=%d WAN %s GW %s\n",
      (int)WiFi.status(),staHasIp?1:0,natActive?1:0,(int)WiFi.softAPgetStationNum(),
      WiFi.localIP().toString().c_str(),WiFi.gatewayIP().toString().c_str());
  }
  delay(3);
}
