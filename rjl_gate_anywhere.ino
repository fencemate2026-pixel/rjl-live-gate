/*
  RJL Gate — "Anywhere" firmware
  Board: Wemos D1 Mini (ESP8266)
  Libraries: PubSubClient (Nick O'Leary), WiFiManager (tzapu). BearSSL ships with core.

  TWO PRODUCT MODES — controlled at the bench by which relay you wire:
   - STANDARD (1 relay):  Relay 1 only. Momentary open trigger. Sold outright.
   - MAINTENANCE (2 relay): Relay 1 = open trigger. Relay 2 = HOLD-OPEN, wired
     across the gate operator's hold-open / timer input. RJL can suspend the
     service remotely (held open) if the monthly payment lapses. Never locks shut.

  WIFI: field-provisioned via captive portal (see RJL-Gate-<chip> hotspot).

  SECURITY:
   - OPEN commands  (topic .../cmd)     : HMAC-signed + 30s freshness + anti-replay.
   - HOLD commands  (topic .../control) : HMAC-signed + anti-replay, RETAINED (no
     freshness window, so a suspend applies whenever the unit next comes online).

  WIRING:
   - Relay 1 IN -> D1 (GPIO5)  across the operator's OPEN / push-button terminals.
   - Relay 2 IN -> D2 (GPIO4)  across the operator's HOLD-OPEN / TIMER terminals.
   - Both relay boards: VCC->5V, GND->G.
*/

#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ESP8266WebServer.h>
#include <WiFiManager.h>
#include <bearssl/bearssl.h>
#include <time.h>

// ==================  PER-UNIT IDENTITY — set at the bench  ==================
const char* GATE_ID     = "demo-0001";
const char* HMAC_SECRET = "952637466aae5d1e751098b9a9c57b80";   // unique per unit
const char* LOCAL_PIN   = "1234";
// ===========================================================================

const char* MQTT_HOST = "71efb01a3c524802bcb0914de069ddf0.s1.eu.hivemq.cloud";
const int   MQTT_PORT = 8883;
const char* MQTT_USER = "RJLCOMMERCIAL";
const char* MQTT_PASS = "Alebakis1!";
const char* SETUP_AP_PASS = "rjlsetup";

const int64_t FRESH_MS = 30000;

// ---- Relays ----
const uint8_t  RELAY_GPIO  = 5;    // D1 — open trigger (momentary)
const uint8_t  RELAY2_GPIO = 4;    // D2 — hold-open (maintained) [maintenance units]
const bool     RELAY_ON    = LOW;  // active-LOW boards
const uint16_t PULSE_MS    = 600;

char topicCmd[64];
char topicStatus[64];
char topicCtrl[64];

WiFiClientSecure net;
PubSubClient      mqtt(net);
ESP8266WebServer  web(80);
unsigned long     lastReconnect = 0;
uint64_t          lastTs     = 0;   // anti-replay: open commands
uint64_t          lastCtrlTs = 0;   // anti-replay: control commands
bool              suspended  = false;

// ---------------- crypto ----------------
static void hmacSha256(const char* key, const char* msg, uint8_t out[32]) {
  br_hmac_key_context kc; br_hmac_key_init(&kc, &br_sha256_vtable, key, strlen(key));
  br_hmac_context ctx;    br_hmac_init(&ctx, &kc, 0);
  br_hmac_update(&ctx, msg, strlen(msg)); br_hmac_out(&ctx, out);
}
static void toHex(const uint8_t* in, size_t n, char* out){
  static const char* H="0123456789abcdef";
  for(size_t i=0;i<n;i++){out[i*2]=H[in[i]>>4];out[i*2+1]=H[in[i]&0xf];} out[n*2]='\0';
}
static bool ctEqual(const char* a,const char* b,size_t n){
  uint8_t d=0; for(size_t i=0;i<n;i++) d|=(uint8_t)(a[i]^b[i]); return d==0;
}
static bool timeSynced(){ return time(nullptr) > 1700000000; }

// pull "sig":"<64hex>" -> out[65]; returns true if 64 chars found
static bool getSig(const char* msg, char* out){
  const char* s=strstr(msg,"\"sig\":\""); if(!s) return false; s+=7;
  size_t i=0; while(i<64 && s[i] && s[i]!='"'){ out[i]=s[i]; i++; } out[i]='\0';
  return i==64;
}

// ---------------- relay / status ----------------
void pulseRelay(){
  Serial.println(F("[relay] pulse"));
  digitalWrite(RELAY_GPIO, RELAY_ON); delay(PULSE_MS); digitalWrite(RELAY_GPIO, !RELAY_ON);
}
void setHoldOpen(bool on){
  suspended = on;
  digitalWrite(RELAY2_GPIO, on ? RELAY_ON : !RELAY_ON);   // closed+held = gate open
  Serial.println(on ? F("[hold] SUSPENDED — gate held open") : F("[hold] active — normal operation"));
}
void publishStatus(const char* state){
  char buf[128];
  snprintf(buf,sizeof(buf),"{\"id\":\"%s\",\"state\":\"%s\",\"suspended\":%s}",
           GATE_ID, state, suspended?"true":"false");
  mqtt.publish(topicStatus, buf, true);
}

// ---------------- OPEN command (cmd topic) ----------------
void handleCmd(const char* msg){
  if(suspended){ Serial.println(F("[verify] ignored: service suspended")); return; }
  if(!timeSynced()){ Serial.println(F("[verify] reject: clock not synced")); return; }
  const char* p=strstr(msg,"\"ts\":"); if(!p){Serial.println(F("[verify] reject: no ts"));return;}
  uint64_t ts=strtoull(p+5,nullptr,10);
  char sig[65]; if(!getSig(msg,sig)){Serial.println(F("[verify] reject: bad sig"));return;}
  char canon[96]; snprintf(canon,sizeof(canon),"open|%s|%llu",GATE_ID,(unsigned long long)ts);
  uint8_t mac[32]; char exp[65]; hmacSha256(HMAC_SECRET,canon,mac); toHex(mac,32,exp);
  if(!ctEqual(sig,exp,64)){Serial.println(F("[verify] reject: signature mismatch"));return;}
  int64_t nowMs=(int64_t)time(nullptr)*1000LL,skew=nowMs-(int64_t)ts; if(skew<0)skew=-skew;
  if(skew>FRESH_MS){Serial.println(F("[verify] reject: stale/future"));return;}
  if(ts<=lastTs){Serial.println(F("[verify] reject: replay"));return;}
  lastTs=ts;
  Serial.println(F("[verify] OK -> opening")); pulseRelay(); publishStatus("opened");
}

// ---------------- HOLD / suspend command (control topic) ----------------
// payload: {"hold":"on"|"off","ts":<ms>,"sig":"<hmac of  hold|<id>|on|<ts> >"}
void handleCtrl(const char* msg){
  const char* h=strstr(msg,"\"hold\":\""); if(!h){Serial.println(F("[ctrl] reject: no hold"));return;}
  h+=8; char hv[4]={0}; size_t i=0; while(i<3 && h[i] && h[i]!='"'){hv[i]=h[i];i++;} hv[i]='\0';
  if(strcmp(hv,"on")&&strcmp(hv,"off")){Serial.println(F("[ctrl] reject: bad hold value"));return;}
  const char* p=strstr(msg,"\"ts\":"); if(!p){Serial.println(F("[ctrl] reject: no ts"));return;}
  uint64_t ts=strtoull(p+5,nullptr,10);
  char sig[65]; if(!getSig(msg,sig)){Serial.println(F("[ctrl] reject: bad sig"));return;}
  char canon[96]; snprintf(canon,sizeof(canon),"hold|%s|%s|%llu",GATE_ID,hv,(unsigned long long)ts);
  uint8_t mac[32]; char exp[65]; hmacSha256(HMAC_SECRET,canon,mac); toHex(mac,32,exp);
  if(!ctEqual(sig,exp,64)){Serial.println(F("[ctrl] reject: signature mismatch"));return;}
  if(ts<=lastCtrlTs){Serial.println(F("[ctrl] reject: replay"));return;}   // no freshness: retained
  lastCtrlTs=ts;
  setHoldOpen(strcmp(hv,"on")==0);
  publishStatus(suspended?"suspended":"active");
}

void onMessage(char* topic, byte* payload, unsigned int len){
  char msg[256]; unsigned int n=len<sizeof(msg)-1?len:sizeof(msg)-1;
  memcpy(msg,payload,n); msg[n]='\0';
  if(!strcmp(topic,topicCtrl)) handleCtrl(msg);
  else                          handleCmd(msg);
}

void mqttConnect(){
  char clientId[48]; snprintf(clientId,sizeof(clientId),"%s-%06x",GATE_ID,ESP.getChipId());
  Serial.print(F("[mqtt] connecting... "));
  if(mqtt.connect(clientId,MQTT_USER,MQTT_PASS)){
    Serial.println(F("OK"));
    mqtt.subscribe(topicCmd);
    mqtt.subscribe(topicCtrl);          // receives retained suspend state on connect
    Serial.print(F("[mqtt] subscribed: ")); Serial.print(topicCmd);
    Serial.print(F("  +  ")); Serial.println(topicCtrl);
    publishStatus(suspended?"suspended":"online");
  } else { Serial.print(F("FAILED, state=")); Serial.println(mqtt.state()); }
}

// ---------------- on-site tap page ----------------
const char PAGE[] PROGMEM = R"HTML(
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<title>RJL Gate</title><style>
 :root{--navy:#13284b;--orange:#ff6b00}
 *{box-sizing:border-box;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif}
 body{margin:0;background:var(--navy);color:#fff;height:100vh;display:flex;
   flex-direction:column;align-items:center;justify-content:center;gap:22px}
 h1{margin:0;font-size:20px;letter-spacing:.5px}
 .pin{font-size:28px;letter-spacing:8px;text-align:center;width:200px;padding:12px;
   border-radius:10px;border:none;background:#0e1f3a;color:#fff}
 .btn{background:var(--orange);color:#fff;border:none;border-radius:14px;
   width:220px;height:120px;font-size:30px;font-weight:700;cursor:pointer}
 .btn:active{transform:scale(.97)}.foot{color:#43597e;font-size:12px}.msg{height:18px;font-size:14px}
</style></head><body>
 <h1>RJL&nbsp;GATE</h1>
 <input id="pin" class="pin" inputmode="numeric" maxlength="8" placeholder="PIN">
 <button class="btn" onclick="go()">OPEN</button>
 <div id="msg" class="msg"></div><div class="foot">on-site control</div>
<script>function go(){var p=document.getElementById('pin').value;
 document.getElementById('msg').textContent='...';
 fetch('/open?pin='+encodeURIComponent(p)).then(r=>r.text())
  .then(t=>{document.getElementById('msg').textContent=t;})
  .catch(function(){document.getElementById('msg').textContent='no connection';});}
</script></body></html>
)HTML";

void handleRoot(){ web.send_P(200,"text/html",PAGE); }
unsigned long lockUntil=0; uint8_t badPins=0;
void handleOpen(){
  if(suspended){ web.send(200,"text/plain","service suspended"); return; }
  if(millis()<lockUntil){ web.send(429,"text/plain","locked - wait"); return; }
  if(web.arg("pin")==LOCAL_PIN){ badPins=0; pulseRelay(); publishStatus("opened");
    web.send(200,"text/plain","gate opening");
  } else { if(++badPins>=5){ lockUntil=millis()+60000UL; badPins=0; }
    web.send(200,"text/plain","wrong PIN"); }
}
void handleForget(){
  // Same PIN gate as /open — otherwise any LAN client can wipe WiFi and force
  // the captive portal, taking the gate offline until physical re-provision.
  if(millis()<lockUntil){ web.send(429,"text/plain","locked - wait"); return; }
  if(web.arg("pin")!=LOCAL_PIN){
    if(++badPins>=5){ lockUntil=millis()+60000UL; badPins=0; }
    web.send(200,"text/plain","wrong PIN");
    return;
  }
  badPins=0;
  web.send(200,"text/plain","forgetting WiFi - reopening setup");
  delay(400); WiFiManager wm; wm.resetSettings(); ESP.restart();
}

void setup(){
  Serial.begin(115200); delay(200);
  Serial.println(F("\n[boot] RJL Gate Anywhere (2-relay / managed)"));

  pinMode(RELAY_GPIO,OUTPUT);  digitalWrite(RELAY_GPIO,!RELAY_ON);    // open trigger OFF
  pinMode(RELAY2_GPIO,OUTPUT); digitalWrite(RELAY2_GPIO,!RELAY_ON);   // hold-open OFF (normal)

  snprintf(topicCmd,   sizeof(topicCmd),   "rjl/gate/%s/cmd",     GATE_ID);
  snprintf(topicStatus,sizeof(topicStatus),"rjl/gate/%s/status",  GATE_ID);
  snprintf(topicCtrl,  sizeof(topicCtrl),  "rjl/gate/%s/control", GATE_ID);

  char apName[32]; snprintf(apName,sizeof(apName),"RJL-Gate-%06x",ESP.getChipId());
  WiFiManager wm;
  wm.setConfigPortalTimeout(0);          // stay in setup until configured
  wm.setConnectTimeout(20);
  Serial.print(F("[wifi] connecting / setup AP: ")); Serial.println(apName);
  if(!wm.autoConnect(apName, SETUP_AP_PASS)){ Serial.println(F("[wifi] timeout, restart")); delay(1000); ESP.restart(); }
  Serial.print(F("[wifi] connected, IP ")); Serial.println(WiFi.localIP());

  configTime(0,0,"pool.ntp.org","time.nist.gov");
  Serial.print(F("[time] syncing"));
  unsigned long t0=millis(); while(!timeSynced()&&millis()-t0<15000){delay(400);Serial.print('.');}
  Serial.println(timeSynced()?F("\n[time] synced"):F("\n[time] NOT synced"));

  net.setInsecure(); net.setBufferSizes(512,512);
  mqtt.setServer(MQTT_HOST,MQTT_PORT); mqtt.setCallback(onMessage); mqtt.setBufferSize(512);

  web.on("/",handleRoot); web.on("/open",handleOpen); web.on("/forget",handleForget);
  web.begin(); Serial.println(F("[web] on-site page up"));
}

void loop(){
  if(WiFi.status()!=WL_CONNECTED){ delay(500); return; }
  if(!mqtt.connected()){ unsigned long now=millis();
    if(now-lastReconnect>3000){ lastReconnect=now; mqttConnect(); } }
  else { mqtt.loop(); }
  web.handleClient();
}
