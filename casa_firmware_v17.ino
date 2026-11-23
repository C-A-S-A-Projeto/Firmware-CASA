/*
 * PROJETO C.A.S.A. - Firmware ESP32-S3 (N16R8) - v2.10.1 (PROTOTIPO, endurecido)
 *
 * Fluxo desta versao:  ESP32  <->  Firebase (Firestore + RTDB)  <->  App/Site
 * O aparelho NAO fala com a API. Ele le/escreve direto no Firestore/RTDB pela API REST.
 *
 * Melhorias v2.10.x:
 *  - Protecao de boot nos botoes: le estado real apos setup() e ignora transientes por 600 ms
 *  - Exibe motivo do ultimo reset no Serial e no OLED no boot (diagnostico de brownout/panic/WDT)
 *  - Wi-Fi offline protegido: persistent(false), autoReconnect(false), TxPower reduzido,
 *    setSleep(true) quando desconectado e scan passivo antes de tentar WiFi.begin()
 *  - Handshake de re-pareamento apos BLE (repar/rep_base na NVS) para nao puxar conta antiga
 *  - Sync incremental por id|sha256, manifesto salvo a cada arquivo, redesenho condicional
 *    e fast-path de download (pula 2 consultas TLS quando arquivo/blocos vem na categoria)
 *  - Thread-safety corrigido entre Core 0 e Core 1 (temRedesConfiguradas)
 */

#include <Arduino.h>
#include <SPI.h>
#include <Wire.h>
#include <SD.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <WebServer.h>
#include <HardwareSerial.h>
#include <stdarg.h>
#include <esp_system.h>
#if __has_include(<esp_mac.h>)
  #include <esp_mac.h>
#endif
#include <time.h>
#include <vector>
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/base64.h"
#include <Preferences.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/timers.h>
#include <ArduinoJson.h>          // v7.x
#include <Adafruit_GFX.h>
#include <Adafruit_ST7789.h>
#include <Adafruit_SSD1306.h>
#include <TJpg_Decoder.h>
#include "Audio.h"

// Declarado aqui no topo: o Arduino gera prototipos automaticos de funcoes antes das structs do meio do arquivo
struct RedeWifi { String ssid; String pass; };

// =====================================================================
// LOGS: Serial (USB + UART0) + buffer circular em RAM + servidor web/telnet
// =====================================================================
#define LOG_SERVER_ATIVO   1      // 1 = sobe o servidor de logs quando houver Wi-Fi | 0 = desligado (versao entregue)
#define LOG_RING_TAM       8192   // bytes de historico guardados para a pagina /logs e para o telnet
#define LOG_PORTA_HTTP     80
#define LOG_PORTA_TELNET   23

// Potencia TX do Wi-Fi: reduz pico de corrente na bateria (ajuda a evitar brownout).
// Se precisar de mais alcance em rede longe do roteador, suba para WIFI_POWER_17dBm ou WIFI_POWER_19_5dBm.
#define WIFI_TX_POWER      WIFI_POWER_15dBm

volatile bool logServerNoAr = false;
String logUrlEnviada = "";        // ultimo endereco gravado em dispositivos/{MAC}.log_url (so a task de rede mexe)
unsigned long proxLogUrlMs = 0;

#if LOG_SERVER_ATIVO
static char logRing[LOG_RING_TAM];
static uint32_t logTotal = 0;     // total de bytes ja escritos (so cresce)
static portMUX_TYPE logMux = portMUX_INITIALIZER_UNLOCKED;

static void logAnexar(const uint8_t* d, size_t n) {
  portENTER_CRITICAL(&logMux);
  for (size_t i = 0; i < n; i++) logRing[(logTotal + i) % LOG_RING_TAM] = (char)d[i];
  logTotal += n;
  portEXIT_CRITICAL(&logMux);
}

static size_t logLer(uint32_t& desde, char* out, size_t max) {
  size_t n = 0;
  portENTER_CRITICAL(&logMux);
  if (logTotal - desde > LOG_RING_TAM) desde = logTotal - LOG_RING_TAM;
  while (desde != logTotal && n < max) { out[n++] = logRing[desde % LOG_RING_TAM]; desde++; }
  portEXIT_CRITICAL(&logMux);
  return n;
}
#endif

// Tudo que o firmware escreve em "Serial" vai para USB, UART0 (GPIO 43/44) e para o buffer de logs
class LogSerialClass : public Stream {
public:
  void begin(unsigned long baud) {
    ::Serial.begin(baud);
#if ARDUINO_USB_CDC_ON_BOOT
    ::Serial.setTxTimeoutMs(0);   // sem PC na USB, nao trava o firmware esperando o buffer esvaziar
    Serial0.begin(baud);
#endif
  }
  int available() override {
    int n = ::Serial.available();
#if ARDUINO_USB_CDC_ON_BOOT
    if (!n) n = Serial0.available();
#endif
    return n;
  }
  int read() override {
    if (::Serial.available()) return ::Serial.read();
#if ARDUINO_USB_CDC_ON_BOOT
    if (Serial0.available()) return Serial0.read();
#endif
    return -1;
  }
  int peek() override {
    if (::Serial.available()) return ::Serial.peek();
#if ARDUINO_USB_CDC_ON_BOOT
    if (Serial0.available()) return Serial0.peek();
#endif
    return -1;
  }
  void flush() override {
    ::Serial.flush();
#if ARDUINO_USB_CDC_ON_BOOT
    Serial0.flush();
#endif
  }
  size_t write(uint8_t c) override { return write(&c, 1); }
  size_t write(const uint8_t* b, size_t n) override {
    ::Serial.write(b, n);
#if ARDUINO_USB_CDC_ON_BOOT
    Serial0.write(b, n);
#endif
#if LOG_SERVER_ATIVO
    logAnexar(b, n);
#endif
    return n;
  }
  operator bool() const { return true; }
};

static LogSerialClass LogSerial;
#define Serial LogSerial

// =====================================================================
// CONFIGURACAO DO FIREBASE
// =====================================================================
const char* PROJECT_ID    = "projeto-casa-f4a05";
#if __has_include("segredos.h")
#include "segredos.h"
#endif
#ifndef FIREBASE_API_KEY
#define FIREBASE_API_KEY  ""   // sem segredos.h: o firmware avisa no Serial e no OLED
#endif
const char* FIRMWARE_VER  = "v2.10.1";

#ifndef RTDB_URL
#define RTDB_URL "https://projeto-casa-f4a05-default-rtdb.firebaseio.com"
#endif
#define RTDB_RAIZ_CONTROLE "/dispositivo/controle/"
#define ATUALIZAR_STATUS_CASA 0

// =====================================================================
// PINAGEM (REVISAO ATUALIZADA DA PCB)
// =====================================================================
#define TFT_SCL       5
#define TFT_SDA       4
#define TFT_DC        6
#define TFT_RST      -1

const uint8_t TFT_CS_PINS[8] = { 40, 39, 38, 0, 48, 45, 47, 21 };

#define TFT_ROTACAO_CATEGORIAS  2
#define TFT_ROTACAO_ACOES       0

#define SD_CS        41
#define SD_SCK       42
#define SD_MOSI       2
#define SD_MISO       1

#define I2C_SDA      10
#define I2C_SCL      11
#define MAX17043_ADDR 0x36

#define I2S_DIN      12
#define I2S_BCLK     13
#define I2S_LRC      14

#define MOTOR_VIBR    7

const uint8_t BTN_PINS[8] = { 17, 18, 8, 16, 15, 3, 46, 9 };

// =====================================================================
// BLE
// =====================================================================
#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define MAC_CHAR_UUID       "beb5483e-36e1-4688-b7f5-ea07361b26a9"
#define STATUS_CHAR_UUID    "beb5483e-36e1-4688-b7f5-ea07361b26aa"

// =====================================================================
// CONSTANTES
// =====================================================================
const uint8_t  VOLUME_PADRAO = 18;
const uint8_t  VOLUME_MAXIMO = 21;
const unsigned long DEBOUNCE_MS   = 180;
const unsigned long BOOT_GUARD_MS = 600;   // ignora transientes nos botoes nos primeiros 600 ms apos o boot
const unsigned long WIFI_ESPERA_MIN_MS = 30000;
const unsigned long WIFI_ESPERA_MAX_MS = 300000;
const unsigned long WIFI_TENTATIVA_MS  = 15000;

#define MAX_REDES       5
#define MAX_REDES_SITE  4
const unsigned long SD_RETRY_MS = 5000;

const unsigned long PAREAMENTO_VALIDADE_MS = 540000;
const uint32_t      HEAP_MINIMO_TLS        = 55000;
const size_t        LOG_MAX_BYTES          = 1024UL * 1024UL;
const unsigned long CONFIG_BLE_TIMEOUT_MS  = 300000;

const unsigned long PAREAMENTO_POLL_MS       = 30000;
const unsigned long INTERVALO_TELEMETRIA_MS  = 300000;
const unsigned long INTERVALO_LOG_MS         = 60000;

const char* ARQ_LOG      = "/log_uso.csv";
const char* ARQ_ENVIO    = "/log_envio.csv";
const char* ARQ_META     = "/meta_prancha.json";
const char* ARQ_MANIFEST = "/manifesto.json";
const char* ARQ_TMP_DL   = "/dl.tmp";

// =====================================================================
// INSTANCIAS GLOBAIS
// =====================================================================
SPIClass spiTFT(HSPI);
SPIClass spiSD(FSPI);

SemaphoreHandle_t sdMutex;
SemaphoreHandle_t i2cMutex;
SemaphoreHandle_t metaMutex;
TimerHandle_t vibracaoTimer;

Adafruit_ST7789 tft[8] = {
  Adafruit_ST7789(&spiTFT, TFT_CS_PINS[0], TFT_DC, TFT_RST),
  Adafruit_ST7789(&spiTFT, TFT_CS_PINS[1], TFT_DC, TFT_RST),
  Adafruit_ST7789(&spiTFT, TFT_CS_PINS[2], TFT_DC, TFT_RST),
  Adafruit_ST7789(&spiTFT, TFT_CS_PINS[3], TFT_DC, TFT_RST),
  Adafruit_ST7789(&spiTFT, TFT_CS_PINS[4], TFT_DC, TFT_RST),
  Adafruit_ST7789(&spiTFT, TFT_CS_PINS[5], TFT_DC, TFT_RST),
  Adafruit_ST7789(&spiTFT, TFT_CS_PINS[6], TFT_DC, TFT_RST),
  Adafruit_ST7789(&spiTFT, TFT_CS_PINS[7], TFT_DC, TFT_RST)
};

Adafruit_SSD1306 oled(128, 32, &Wire, -1);
Audio audio;
Preferences prefs;

enum ModoOperacao { MODO_CONFIG, MODO_UTILIZACAO };
ModoOperacao modoAtual = MODO_UTILIZACAO;

enum StatusSync { SYNC_DESCONHECIDO = 0, SYNC_OK, SYNC_NAO_PAREADO, SYNC_ERRO_ACESSO, SYNC_ERRO };
volatile int statusSync = SYNC_DESCONHECIDO;

volatile uint8_t categoriaAtiva = 1;
volatile bool sdDisponivel = false;
volatile bool oledOk = false;
volatile bool bleRecebeuConfig = false;
volatile bool recarregarTelasPendente = false;
volatile bool temRedesConfiguradas = false;   // lido pelo Core 1 (OLED) de forma segura
volatile int  volumePendente = -1;
volatile uint8_t telaAtivaRender = 0;

String bleBufferAcumulado = "";
char blePin[8] = "";
volatile bool blePinRenovar = false;
volatile uint8_t blePinFalhas = 0;
volatile unsigned long bleBloqueadoAteMs = 0;
BLECharacteristic* pBleStatus = nullptr;
String nomeBleAtual = "";

bool categoriaExiste[3] = { false, false, false };
bool botaoAtivo[5]      = { false, false, false, false, false };
unsigned long ultimaTentativaSD = 0;
unsigned long bootFimSetupMs = 0;

struct BotaoMeta { String id; String rotulo; };
struct CategoriaMeta { String nome; BotaoMeta botoes[5]; };
CategoriaMeta pranchaMeta[3];
String modoContexto = "casa";

uint32_t bootCount = 0;
uint32_t clickSeq = 0;
int32_t configVersaoLocal = -1;
bool alertaBateriaEnviado = false;

volatile bool ntpMarcadorPendente = false;
volatile uint32_t ntpUptimeSync = 0;
volatile uint32_t ntpEpochSync = 0;

#define LOG_FILA_TAM 32
struct LogEvento {
  uint32_t seqId;
  uint32_t ts;
  bool     epoch;
  uint8_t  cat;
  uint8_t  btn;
  char     botaoId[24];
  char     catNome[48];
  char     rotulo[64];
};
LogEvento logFila[LOG_FILA_TAM];
volatile uint8_t logHead = 0;
volatile uint8_t logTail = 0;

bool estadoAnteriorBtn[8] = { HIGH, HIGH, HIGH, HIGH, HIGH, HIGH, HIGH, HIGH };
unsigned long ultimoCliqueBtn[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

String wifiSSID = "";
String wifiPass = "";

RedeWifi redes[MAX_REDES];
int      numRedes = 0;
int      redeIdx = 0;
uint8_t  wifiKey[32];
bool     temChaveWifi = false;
int32_t  wifiVersaoLocal = -1;
String   wifiStatus = "sem_chave";

String ownerUid = "";
bool   reparPendente = false;     // NVS "repar": true apos config BLE ate o app regravar dispositivos/{MAC}
String reparBase = "-";           // NVS "rep_base": marca do documento antigo visto na 1a leitura apos BLE
String pinPendente = "";
String macComPontos = "";
String macSemPontos = "";
String macUrl = "";

char codigoPareamento[8] = { 0 };
unsigned long codigoGeradoMs = 0;
volatile bool forcarTelemetria = false;
bool configPodeExpirar = false;
unsigned long inicioConfigMs = 0;

String idToken = "";
String refreshToken = "";
unsigned long tokenExpiraMs = 0;

JsonDocument manifesto;           // slot -> "id|sha" da midia gravada no SD (so Core 0 apos boot)
bool houveMudancaPrancha = false; // controla se precisa redesenhar TFTs ao fim do sync
bool mostrouOledSync = false;     // so mostra "SINCRONIZANDO..." no OLED quando realmente baixar algo

// =====================================================================
// UTILITARIOS
// =====================================================================
const char* nomeMotivoReset(esp_reset_reason_t rr) {
  switch (rr) {
    case ESP_RST_BROWNOUT:  return "BROWNOUT";
    case ESP_RST_PANIC:     return "PANIC";
    case ESP_RST_TASK_WDT:  return "TASK_WDT";
    case ESP_RST_INT_WDT:   return "INT_WDT";
    case ESP_RST_WDT:       return "WDT";
    case ESP_RST_POWERON:   return "POWERON";
    case ESP_RST_SW:        return "SW";
    case ESP_RST_DEEPSLEEP: return "DEEPSLEEP";
    case ESP_RST_EXT:       return "EXT_PIN";
    default:                return "OUTRO";
  }
}

void inicializarMacStrings() {
  uint8_t mac[6] = {0};
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  char a[18], b[13], c[28];
  snprintf(a, sizeof(a), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  snprintf(b, sizeof(b), "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  snprintf(c, sizeof(c), "%02X%%3A%02X%%3A%02X%%3A%02X%%3A%02X%%3A%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  macComPontos = String(a);
  macSemPontos = String(b);
  macUrl = String(c);
}

bool relogioValido() { return time(nullptr) > 1700000000; }

bool heapSuficienteParaTLS() {
  uint32_t livre = ESP.getFreeHeap();
  if (livre < HEAP_MINIMO_TLS) {
    Serial.printf("[REDE] Heap baixo (%u bytes): adiando conexao segura.\n", (unsigned)livre);
    return false;
  }
  return true;
}

String isoDeEpoch(uint32_t e) {
  time_t t = (time_t)e;
  struct tm tmInfo;
  gmtime_r(&t, &tmInfo);
  char buf[25];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmInfo);
  return String(buf);
}

int calcularQualidadeWifiPct() {
  if (WiFi.status() != WL_CONNECTED) return 0;
  int rssi = WiFi.RSSI();
  if (rssi <= -100) return 0;
  if (rssi >= -50) return 100;
  return 2 * (rssi + 100);
}

String jsStr(JsonVariantConst v, const String& padrao) {
  const char* s = v.as<const char*>();
  return s ? String(s) : padrao;
}

int fsInt(JsonVariantConst campo, int padrao = 0) {
  JsonVariantConst x = campo["integerValue"];
  if (x.is<const char*>()) return atoi(x.as<const char*>());
  if (x.is<int>()) return x.as<int>();
  JsonVariantConst d = campo["doubleValue"];
  if (d.is<double>()) return (int)d.as<double>();
  return padrao;
}

String fsStr(JsonVariantConst campo) { return jsStr(campo["stringValue"], ""); }

void copiarSanitizado(char* dst, size_t tam, const String& s) {
  size_t n = 0;
  size_t len = s.length();
  for (size_t i = 0; i < len && n < tam - 1; i++) {
    char c = s[i];
    dst[n++] = (c == ',' || c == '\n' || c == '\r') ? ' ' : c;
  }
  dst[n] = 0;
  if (len > n) {
    size_t i = n;
    while (i > 0 && (((uint8_t)dst[i - 1]) & 0xC0) == 0x80) i--;
    if (i > 0 && (((uint8_t)dst[i - 1]) & 0x80)) i--;
    dst[i] = 0;
  }
}

String nomeCategoriaSeguro(int idx) {
  String r = "Cat " + String(idx + 1);
  if (idx >= 0 && idx < 3 && xSemaphoreTake(metaMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
    r = pranchaMeta[idx].nome;
    xSemaphoreGive(metaMutex);
  }
  return r;
}

String textoParaOLED(const String& in, size_t maxLen) {
  static const char mapa[] = "AAAAAAACEEEEIIIIDNOOOOOxOUUUUYTsaaaaaaaceeeeiiiidnooooo/ouuuuyty";
  String out;
  size_t n = in.length();
  for (size_t i = 0; i < n && out.length() < maxLen; i++) {
    uint8_t c = (uint8_t)in[i];
    if (c >= 0x20 && c < 0x7F) out += (char)c;
    else if (c == 0xC3 && i + 1 < n) {
      uint8_t d = (uint8_t)in[i + 1];
      if (d >= 0x80 && d <= 0xBF) { out += mapa[d - 0x80]; i++; }
    }
  }
  return out;
}

String modoSeguro() {
  String r = "casa";
  if (xSemaphoreTake(metaMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
    r = modoContexto;
    xSemaphoreGive(metaMutex);
  }
  return r;
}

// =====================================================================
// MOTOR VIA TIMER FREERTOS
// =====================================================================
void callbackDesligarVibracao(TimerHandle_t xTimer) { digitalWrite(MOTOR_VIBR, LOW); }

void iniciarVibracao(uint16_t duracaoMs = 90) {
  digitalWrite(MOTOR_VIBR, HIGH);
  if (vibracaoTimer != NULL) {
    xTimerChangePeriod(vibracaoTimer, pdMS_TO_TICKS(duracaoMs), 0);
    xTimerStart(vibracaoTimer, 0);
  }
}

// =====================================================================
// BATERIA (MAX17043) E OLED
// =====================================================================
float lerPorcentagemBateriaInterno() {
  Wire.beginTransmission(MAX17043_ADDR);
  Wire.write(0x04);
  if (Wire.endTransmission(false) != 0) return -1.0f;
  if (Wire.requestFrom((uint8_t)MAX17043_ADDR, (uint8_t)2) == 2) {
    uint8_t msb = Wire.read();
    uint8_t lsb = Wire.read();
    float soc = msb + (lsb / 256.0f);
    return (soc > 100.0f) ? 100.0f : soc;
  }
  return -1.0f;
}

float obterBateriaThreadSafe() {
  float b = -1.0f;
  if (xSemaphoreTake(i2cMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    b = lerPorcentagemBateriaInterno();
    xSemaphoreGive(i2cMutex);
  }
  return b;
}

void mostrarMensagemOLED(const char* l1, const char* l2 = "", const char* l3 = "") {
  if (!oledOk) return;
  if (xSemaphoreTake(i2cMutex, pdMS_TO_TICKS(150)) == pdTRUE) {
    oled.clearDisplay();
    oled.setTextSize(1);
    oled.setCursor(0, 0);
    oled.println(l1);
    if (strlen(l2) > 0) oled.println(l2);
    if (strlen(l3) > 0) oled.println(l3);
    oled.display();
    xSemaphoreGive(i2cMutex);
  }
}

void oledCodigoGrande(const char* rotulo, const char* codigo) {
  oled.clearDisplay();
  oled.setTextSize(1);
  oled.setCursor(0, 0);
  oled.print(rotulo);
  oled.setTextSize(3);
  int w = (int)strlen(codigo) * 18;
  oled.setCursor((128 - w) / 2, 8);
  oled.print(codigo);
  oled.setTextSize(1);
  oled.display();
}

void atualizarOLEDStatus() {
  if (!oledOk) return;

  String catNome = textoParaOLED(nomeCategoriaSeguro((int)categoriaAtiva - 1), 21);

  if (xSemaphoreTake(i2cMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    oled.clearDisplay();
    oled.setCursor(0, 0);

    char cod[8];
    strncpy(cod, codigoPareamento, sizeof(cod) - 1);
    cod[sizeof(cod) - 1] = 0;
    if (temRedesConfiguradas && WiFi.status() == WL_CONNECTED &&
        statusSync == SYNC_NAO_PAREADO && cod[0] != 0) {
      oledCodigoGrande("Codigo de pareamento:", cod);
      xSemaphoreGive(i2cMutex);
      return;
    }

    float bat = lerPorcentagemBateriaInterno();
    char bt[8];
    if (bat >= 0.0f) snprintf(bt, sizeof(bt), "%.0f%%", bat);
    else             snprintf(bt, sizeof(bt), "--");

    oled.setTextSize(2);
    if (!sdDisponivel) oled.println("ERRO SD!");
    else               oled.printf("Cat %d %4s", categoriaAtiva, bt);

    oled.setTextSize(1);
    oled.setCursor(0, 16);
    if (!sdDisponivel) oled.println("Cartao SD ausente");
    else               oled.println(catNome.c_str());

    oled.setCursor(0, 24);
    if (!temRedesConfiguradas)                  oled.println("Cfg: Segure Cat 1+2+3");
    else if (WiFi.status() != WL_CONNECTED)     oled.println("Sem conexao (Local)");
    else if (strlen(FIREBASE_API_KEY) == 0)     oled.println("Falta chave de API");
    else if (statusSync == SYNC_NAO_PAREADO)    oled.println("Aguardando pareamento");
    else if (statusSync == SYNC_ERRO_ACESSO)    oled.println("Erro acesso a nuvem");
    else                                        { if (logServerNoAr) oled.printf("IP %s\n", WiFi.localIP().toString().c_str()); else oled.println("Rede: ONLINE"); }

    oled.display();
    xSemaphoreGive(i2cMutex);
  }
}

// =====================================================================
// SD: HELPERS
// =====================================================================
bool sdExiste(const char* caminho) {
  if (!sdDisponivel) return false;
  bool ok = false;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(300)) == pdTRUE) {
    ok = SD.exists(caminho);
    xSemaphoreGive(sdMutex);
  }
  return ok;
}

bool resolverCaminhoAudio(uint8_t cat, uint8_t botao, char* out, size_t tam) {
  snprintf(out, tam, "/cat%d/b%d.mp3", cat, botao);
  if (sdExiste(out)) return true;
  snprintf(out, tam, "/cat%d/b%d.wav", cat, botao);
  return sdExiste(out);
}

bool montarSD() {
  bool ok = false;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    SD.end();
    ok = SD.begin(SD_CS, spiSD, 4000000, "/sd", 5);
    if (!ok) ok = SD.begin(SD_CS, spiSD, 1000000, "/sd", 5);
    xSemaphoreGive(sdMutex);
  }
  return ok;
}

void salvarMetadadosPranchaNoSD() {
  if (!sdDisponivel) return;
  JsonDocument doc;
  JsonArray arrCats = doc["cats"].to<JsonArray>();
  if (xSemaphoreTake(metaMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
    for (int c = 0; c < 3; c++) {
      JsonObject oCat = arrCats.add<JsonObject>();
      oCat["nome"] = pranchaMeta[c].nome;
      JsonArray arrBtns = oCat["btns"].to<JsonArray>();
      for (int b = 0; b < 5; b++) {
        JsonObject oBtn = arrBtns.add<JsonObject>();
        oBtn["id"] = pranchaMeta[c].botoes[b].id;
        oBtn["rotulo"] = pranchaMeta[c].botoes[b].rotulo;
      }
    }
    doc["modo"] = modoContexto;
    xSemaphoreGive(metaMutex);
  }
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    if (SD.exists(ARQ_META)) SD.remove(ARQ_META);
    File f = SD.open(ARQ_META, FILE_WRITE);
    if (f) { serializeJson(doc, f); f.close(); }
    xSemaphoreGive(sdMutex);
  }
}

void carregarMetadadosPranchaDoSD() {
  if (xSemaphoreTake(metaMutex, pdMS_TO_TICKS(300)) != pdTRUE) return;
  for (int c = 0; c < 3; c++) {
    pranchaMeta[c].nome = "Cat " + String(c + 1);
    for (int b = 0; b < 5; b++) {
      pranchaMeta[c].botoes[b].id = "";
      pranchaMeta[c].botoes[b].rotulo = "Botao " + String(b + 1);
    }
  }
  xSemaphoreGive(metaMutex);

  if (!sdDisponivel) return;
  JsonDocument doc;
  bool lido = false;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    if (SD.exists(ARQ_META)) {
      File f = SD.open(ARQ_META, FILE_READ);
      if (f) { lido = (deserializeJson(doc, f) == DeserializationError::Ok); f.close(); }
    }
    xSemaphoreGive(sdMutex);
  }
  if (!lido) return;

  if (xSemaphoreTake(metaMutex, pdMS_TO_TICKS(300)) == pdTRUE) {
    JsonArray arrCats = doc["cats"].as<JsonArray>();
    for (int c = 0; c < 3 && c < (int)arrCats.size(); c++) {
      pranchaMeta[c].nome = jsStr(arrCats[c]["nome"], "Cat " + String(c + 1));
      JsonArray arrBtns = arrCats[c]["btns"].as<JsonArray>();
      for (int b = 0; b < 5 && b < (int)arrBtns.size(); b++) {
        pranchaMeta[c].botoes[b].id = jsStr(arrBtns[b]["id"], "");
        pranchaMeta[c].botoes[b].rotulo = jsStr(arrBtns[b]["rotulo"], "Botao " + String(b + 1));
      }
    }
    modoContexto = jsStr(doc["modo"], "casa");
    xSemaphoreGive(metaMutex);
  }
}

void carregarManifesto() {
  manifesto.clear();
  if (!sdDisponivel) return;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    if (SD.exists(ARQ_MANIFEST)) {
      File f = SD.open(ARQ_MANIFEST, FILE_READ);
      if (f) { deserializeJson(manifesto, f); f.close(); }
    }
    xSemaphoreGive(sdMutex);
  }
}

void salvarManifesto() {
  if (!sdDisponivel) return;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    if (SD.exists(ARQ_MANIFEST)) SD.remove(ARQ_MANIFEST);
    File f = SD.open(ARQ_MANIFEST, FILE_WRITE);
    if (f) { serializeJson(manifesto, f); f.close(); }
    xSemaphoreGive(sdMutex);
  }
}

// =====================================================================
// TFT
// =====================================================================
bool tft_output(int16_t x, int16_t y, uint16_t w, uint16_t h, uint16_t* bitmap) {
  if (y >= tft[telaAtivaRender].height()) return 0;
  tft[telaAtivaRender].drawRGBBitmap(x, y, bitmap, w, h);
  return 1;
}

bool desenharImagemTFT(uint8_t indexTela, const char* caminhoSD, bool destacarBorda = false) {
  if (indexTela >= 8) return false;
  bool desenhou = false;

  if (sdDisponivel && xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    telaAtivaRender = indexTela;
    if (SD.exists(caminhoSD)) {
      TJpgDec.drawSdJpg(0, 0, caminhoSD);
      desenhou = true;
    }
    xSemaphoreGive(sdMutex);
  }

  if (!desenhou) tft[indexTela].fillScreen(ST77XX_BLACK);

  if (desenhou && destacarBorda) {
    for (int b = 0; b < 4; b++) {
      tft[indexTela].drawRect(b, b, 240 - (2 * b), 240 - (2 * b), ST77XX_GREEN);
    }
  }
  return desenhou;
}

// =====================================================================
// LOG DE CLIQUES (Core 1)
// =====================================================================
void enfileirarLog(uint8_t cat, uint8_t btn) {
  uint8_t prox = (logHead + 1) % LOG_FILA_TAM;
  if (prox == logTail) logTail = (logTail + 1) % LOG_FILA_TAM;

  LogEvento& e = logFila[logHead];
  e.seqId = ++clickSeq;
  if (relogioValido()) { e.epoch = true;  e.ts = (uint32_t)time(nullptr); }
  else                 { e.epoch = false; e.ts = millis() / 1000; }
  e.cat = cat;
  e.btn = btn;
  e.botaoId[0] = 0; e.catNome[0] = 0; e.rotulo[0] = 0;

  if (xSemaphoreTake(metaMutex, pdMS_TO_TICKS(20)) == pdTRUE) {
    copiarSanitizado(e.catNome, sizeof(e.catNome), pranchaMeta[cat - 1].nome);
    copiarSanitizado(e.botaoId, sizeof(e.botaoId), pranchaMeta[cat - 1].botoes[btn - 1].id);
    copiarSanitizado(e.rotulo, sizeof(e.rotulo), pranchaMeta[cat - 1].botoes[btn - 1].rotulo);
    xSemaphoreGive(metaMutex);
  }
  logHead = prox;
}

void processarLogsPendentesNoSD() {
  bool temLog = (logTail != logHead);
  if ((!temLog && !ntpMarcadorPendente) || audio.isRunning() || !sdDisponivel) return;

  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
    File logFile = SD.open(ARQ_LOG, FILE_APPEND);
    if (logFile && logFile.size() > LOG_MAX_BYTES) {
      logFile.close();
      SD.remove(ARQ_LOG);
      logFile = SD.open(ARQ_LOG, FILE_APPEND);
      if (ntpEpochSync != 0) ntpMarcadorPendente = true;
      Serial.println("[LOG] Log local cheio: registros antigos descartados.");
    }
    if (logFile) {
      if (ntpMarcadorPendente) {
        logFile.printf("#SYNC,%lu,%lu,%lu\n", (unsigned long)bootCount,
                       (unsigned long)ntpUptimeSync, (unsigned long)ntpEpochSync);
        ntpMarcadorPendente = false;
      }
      while (logTail != logHead) {
        const LogEvento& e = logFila[logTail];
        logFile.printf("%lu_%lu,%c,%lu,%d,%d,%s,%s,%s\n",
                       (unsigned long)bootCount, (unsigned long)e.seqId,
                       e.epoch ? 'E' : 'U', (unsigned long)e.ts,
                       e.cat, e.btn, e.botaoId, e.catNome, e.rotulo);
        logTail = (logTail + 1) % LOG_FILA_TAM;
      }
      logFile.close();
    }
    xSemaphoreGive(sdMutex);
  }
}

// =====================================================================
// PRANCHA DE COMUNICACAO (Core 1)
// =====================================================================
bool categoriaTemConteudo(int c) {
  char p[40];
  snprintf(p, sizeof(p), "/cat%d/icone.jpg", c + 1);
  if (sdExiste(p)) return true;
  snprintf(p, sizeof(p), "/cat%d/icone.mp3", c + 1);
  if (sdExiste(p)) return true;
  snprintf(p, sizeof(p), "/cat%d/icone.wav", c + 1);
  if (sdExiste(p)) return true;
  for (int b = 1; b <= 5; b++) {
    snprintf(p, sizeof(p), "/cat%d/b%d.jpg", c + 1, b);
    if (sdExiste(p)) return true;
    if (resolverCaminhoAudio(c + 1, b, p, sizeof(p))) return true;
  }
  return false;
}

void logResumoSD(const char* quando) {
  if (!sdDisponivel) { Serial.printf("[SD] (%s) cartao NAO disponivel\n", quando); return; }
  unsigned long mb = 0;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
    mb = (unsigned long)(SD.cardSize() / (1024ULL * 1024ULL));
    xSemaphoreGive(sdMutex);
  }
  Serial.printf("[SD] (%s) cartao de %lu MB\n", quando, mb);
  for (int c = 1; c <= 3; c++) {
    char p[40], pa[40], linha[110];
    snprintf(p, sizeof(p), "/cat%d/icone.jpg", c);
    int n = snprintf(linha, sizeof(linha), "[SD] cat%d icone=%s |", c, sdExiste(p) ? "OK" : "--");
    for (int b = 1; b <= 5; b++) {
      snprintf(p, sizeof(p), "/cat%d/b%d.jpg", c, b);
      bool img = sdExiste(p);
      bool aud = resolverCaminhoAudio(c, b, pa, sizeof(pa));
      n += snprintf(linha + n, sizeof(linha) - n, " b%d=%s", b, (img && aud) ? "img+aud" : img ? "img" : aud ? "aud" : "--");
    }
    Serial.println(linha);
  }
}

void carregarPranchaCategoria(uint8_t cat, uint8_t catAnterior = 0) {
  categoriaAtiva = cat;
  atualizarOLEDStatus();

  for (int i = 0; i < 3; i++) {
    bool redesenhar = (catAnterior == 0) || ((i + 1) == cat) || ((i + 1) == catAnterior);
    if (!redesenhar) continue;
    char caminhoCat[32];
    snprintf(caminhoCat, sizeof(caminhoCat), "/cat%d/icone.jpg", i + 1);
    desenharImagemTFT(i, caminhoCat, (i + 1) == cat);
  }
  if (catAnterior == 0) {
    for (int i = 0; i < 3; i++) categoriaExiste[i] = categoriaTemConteudo(i);
  }

  for (int i = 0; i < 5; i++) {
    char caminhoBotao[32];
    snprintf(caminhoBotao, sizeof(caminhoBotao), "/cat%d/b%d.jpg", cat, i + 1);
    bool temImagem = desenharImagemTFT(i + 3, caminhoBotao, false);
    char caminhoAudio[32];
    botaoAtivo[i] = temImagem || resolverCaminhoAudio(cat, i + 1, caminhoAudio, sizeof(caminhoAudio));
  }
}

void dispararBotaoComunicacao(uint8_t indexBotao) {
  if (indexBotao >= 5) return;
  if (!botaoAtivo[indexBotao]) {
    Serial.printf("[BTN] Botao %d da Cat %d inativo: sem imagem nem audio no SD\n", indexBotao + 1, categoriaAtiva);
    return;
  }

  uint8_t numeroBotao = indexBotao + 1;
  Serial.printf(">> [ACIONAMENTO] Cat %d | Botao %d\n", categoriaAtiva, numeroBotao);

  iniciarVibracao(90);

  char caminhoAudio[32];
  if (resolverCaminhoAudio(categoriaAtiva, numeroBotao, caminhoAudio, sizeof(caminhoAudio))) {
    if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
      Serial.printf("[AUDIO] Tocando %s\n", caminhoAudio);
      audio.connecttoFS(SD, caminhoAudio);
      xSemaphoreGive(sdMutex);
    } else {
      Serial.println("[AUDIO] SD ocupado: audio nao iniciado");
    }
  } else {
    Serial.printf("[AUDIO] Cat %d Botao %d sem audio no SD (so imagem)\n", categoriaAtiva, numeroBotao);
  }
  enfileirarLog(categoriaAtiva, numeroBotao);
}

bool tocarAudioCategoria(uint8_t cat) {
  char caminho[32];
  snprintf(caminho, sizeof(caminho), "/cat%d/icone.mp3", cat);
  if (!sdExiste(caminho)) {
    snprintf(caminho, sizeof(caminho), "/cat%d/icone.wav", cat);
    if (!sdExiste(caminho)) {
      Serial.printf("[AUDIO] Cat %d sem audio de categoria no SD\n", cat);
      return false;
    }
  }
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    Serial.printf("[AUDIO] Tocando (categoria) %s\n", caminho);
    audio.connecttoFS(SD, caminho);
    xSemaphoreGive(sdMutex);
    return true;
  }
  Serial.println("[AUDIO] SD ocupado: audio da categoria nao iniciado");
  return false;
}

// =====================================================================
// FIREBASE: AUTENTICACAO ANONIMA + REQUISICAO REST
// =====================================================================
bool firebaseGarantirToken() {
  if (strlen(FIREBASE_API_KEY) == 0) return true;
  if (idToken.length() > 0 && (long)(millis() - tokenExpiraMs) < 0) return true;

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  http.setTimeout(15000);
  bool ok = false;
  String novoRefresh = "";
  int expira = 3600;

  if (refreshToken.length() > 0) {
    String url = "https://securetoken.googleapis.com/v1/token?key=" + String(FIREBASE_API_KEY);
    if (http.begin(client, url)) {
      http.addHeader("Content-Type", "application/x-www-form-urlencoded");
      int code = http.POST("grant_type=refresh_token&refresh_token=" + refreshToken);
      if (code == 200) {
        JsonDocument doc;
        if (deserializeJson(doc, http.getString()) == DeserializationError::Ok) {
          idToken = jsStr(doc["id_token"], "");
          novoRefresh = jsStr(doc["refresh_token"], "");
          expira = atoi(doc["expires_in"] | "3600");
          ok = idToken.length() > 0;
        }
      } else if (code == 400) {
        refreshToken = "";
      }
      http.end();
    }
  }

  if (!ok && refreshToken.length() == 0) {
    String url = "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + String(FIREBASE_API_KEY);
    if (http.begin(client, url)) {
      http.addHeader("Content-Type", "application/json");
      int code = http.POST("{\"returnSecureToken\":true}");
      if (code == 200) {
        JsonDocument doc;
        if (deserializeJson(doc, http.getString()) == DeserializationError::Ok) {
          idToken = jsStr(doc["idToken"], "");
          novoRefresh = jsStr(doc["refreshToken"], "");
          expira = atoi(doc["expiresIn"] | "3600");
          ok = idToken.length() > 0;
        }
      } else {
        Serial.printf("[AUTH] Falha no login anonimo: HTTP %d\n", code);
      }
      http.end();
    }
  }

  if (!ok) { idToken = ""; return false; }

  tokenExpiraMs = millis() + (unsigned long)max(60, expira - 120) * 1000UL;
  if (novoRefresh.length() > 0 && novoRefresh != refreshToken) {
    refreshToken = novoRefresh;
    prefs.begin("casa_cfg", false);
    prefs.putString("fb_refresh", refreshToken);
    prefs.end();
  }
  return true;
}

String docUrl(const String& caminho) {
  return "https://firestore.googleapis.com/v1/projects/" + String(PROJECT_ID) +
         "/databases/(default)/documents/" + caminho;
}

int fsRequest(WiFiClientSecure& client, HTTPClient& http, const String& url,
              const char* metodo, const String& corpo = "") {
  if (!firebaseGarantirToken()) return -1;
  http.setConnectTimeout(8000);
  http.setTimeout(20000);
  http.useHTTP10(true);
  if (!http.begin(client, url)) return -1;
  if (idToken.length() > 0 && strlen(FIREBASE_API_KEY) > 0) {
    http.addHeader("Authorization", "Bearer " + idToken);
  }
  if (corpo.length() > 0) http.addHeader("Content-Type", "application/json");
  int code = http.sendRequest(metodo, corpo);
  if (code == 401) { idToken = ""; tokenExpiraMs = 0; }
  return code;
}

// =====================================================================
// DOWNLOAD DE MIDIA (streaming: Base64 -> bytes -> SD, com SHA-256)
// =====================================================================
struct LeitorHttp {
  WiFiClient* s = nullptr;
  uint8_t buf[512];
  int pos = 0, len = 0;
  unsigned long timeoutMs = 15000;

  int lerByte() {
    if (pos >= len) {
      unsigned long t0 = millis();
      for (;;) {
        int disp = s->available();
        if (disp > 0) {
          int n = s->read(buf, (disp < (int)sizeof(buf)) ? disp : (int)sizeof(buf));
          if (n > 0) { len = n; pos = 0; break; }
        } else if (!s->connected()) {
          return -1;
        }
        if (millis() - t0 > timeoutMs) return -2;
        vTaskDelay(pdMS_TO_TICKS(1));
      }
    }
    return buf[pos++];
  }

  bool avancarAteUmDe(const char* a, const char* b) {
    size_t na = strlen(a), nb = strlen(b), ia = 0, ib = 0;
    for (;;) {
      int c = lerByte();
      if (c < 0) return false;
      if (c == (uint8_t)a[ia]) { if (++ia == na) return true; } else ia = (c == (uint8_t)a[0]) ? 1 : 0;
      if (c == (uint8_t)b[ib]) { if (++ib == nb) return true; } else ib = (c == (uint8_t)b[0]) ? 1 : 0;
    }
  }

  bool avancarAte(const char* alvo) {
    size_t n = strlen(alvo), i = 0;
    for (;;) {
      int c = lerByte();
      if (c < 0) return false;
      if (c == (uint8_t)alvo[i]) { if (++i == n) return true; }
      else i = (c == (uint8_t)alvo[0]) ? 1 : 0;
    }
  }
};

int valorBase64(int c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

int valorHex(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool gravarNoSD(File& f, mbedtls_md_context_t& md, const uint8_t* dados, size_t n) {
  if (n == 0) return true;
  unsigned long t0 = millis();
  while (audio.isRunning() && millis() - t0 < 20000) vTaskDelay(pdMS_TO_TICKS(20));
  mbedtls_md_update(&md, dados, n);
  bool ok = false;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
    ok = (f.write(dados, n) == n);
    xSemaphoreGive(sdMutex);
  }
  vTaskDelay(pdMS_TO_TICKS(1));
  return ok;
}

bool baixarBloco(WiFiClientSecure& client, const String& arquivo, int bloco,
                 File& f, mbedtls_md_context_t& md, size_t& totalBytes) {
  HTTPClient http;
  char idb[8];
  snprintf(idb, sizeof(idb), "%04d", bloco);
  int code = fsRequest(client, http, docUrl("arquivos_midia/" + arquivo + "/blocos/" + String(idb)), "GET");
  if (code != 200) {
    Serial.printf("[MIDIA] Bloco %s: HTTP %d\n", idb, code);
    http.end();
    return false;
  }

  LeitorHttp rd;
  rd.s = http.getStreamPtr();
  bool ok = rd.avancarAteUmDe("\"dados_b64\"", "\"b64\"") && rd.avancarAte("\"stringValue\"") && rd.avancarAte("\"");
  if (!ok) Serial.printf("[MIDIA] Bloco %s: campo dados_b64/b64 nao encontrado\n", idb);

  const size_t TAM_SAIDA = 2048;
  uint8_t* saida = ok ? (uint8_t*)malloc(TAM_SAIDA) : nullptr;
  if (ok && !saida) { Serial.println("[MIDIA] Sem RAM"); ok = false; }

  size_t n = 0;
  int q[4], qn = 0;
  while (ok) {
    int c = rd.lerByte();
    if (c < 0) { ok = false; break; }
    if (c == '"') break;
    if (c == '\\') {
      int e = rd.lerByte();
      if (e == 'u') {
        int h[4];
        for (int i = 0; i < 4; i++) h[i] = valorHex(rd.lerByte());
        if (h[0] < 0 || h[1] < 0 || h[2] < 0 || h[3] < 0) { ok = false; break; }
        c = (h[0] << 12) | (h[1] << 8) | (h[2] << 4) | h[3];
      } else if (e < 0) { ok = false; break; }
      else c = e;
    }
    if (c == '=') { q[qn++] = -2; }
    else if (c == '\n' || c == '\r' || c == ' ') { continue; }
    else {
      int v = valorBase64(c);
      if (v < 0) {
        Serial.printf("[MIDIA] Bloco %04d: Base64 invalido (cod %d) apos %u bytes\n", bloco, c, (unsigned)(totalBytes + n));
        ok = false; break;
      }
      q[qn++] = v;
    }
    if (qn == 4) {
      saida[n++] = (q[0] << 2) | (q[1] >> 4);
      if (q[2] != -2) saida[n++] = ((q[1] & 0x0F) << 4) | (q[2] >> 2);
      if (q[2] != -2 && q[3] != -2) saida[n++] = ((q[2] & 0x03) << 6) | q[3];
      qn = 0;
      if (n > TAM_SAIDA - 4) {
        if (!gravarNoSD(f, md, saida, n)) { ok = false; break; }
        totalBytes += n;
        n = 0;
      }
    }
  }
  if (ok && qn != 0) { Serial.printf("[MIDIA] Bloco %04d: Base64 truncado\n", bloco); ok = false; }
  if (ok && n > 0) {
    ok = gravarNoSD(f, md, saida, n);
    totalBytes += n;
  }
  if (saida) free(saida);
  http.end();
  return ok;
}

// Retorno: 0 = ok | 1 = erro temporario (tenta de novo) | 2 = midia inexistente (404)
// Fast-path: se arquivoHint e blocosHint > 0 vieram da categoria, pula 2 consultas TLS extras!
int baixarMidia(WiFiClientSecure& client, const String& uid, const String& midiaId,
                bool ehAudio, const String& base,
                const String& shaHint, const String& arquivoHint, int blocosHint) {
  HTTPClient http;
  String arquivo = arquivoHint;
  String shaEsperado = shaHint;
  int totalBlocos = blocosHint;
  int tamanhoEsperado = 0;

  // Fallback para o formato classico quando o app nao enviou os campos denormalizados
  if (arquivo.length() == 0 || totalBlocos <= 0) {
    int code = fsRequest(client, http, docUrl("usuarios/" + uid + "/midias/" + midiaId), "GET");
    if (code == 404) { Serial.printf("[MIDIA] %s: midias/%s nao existe (404)\n", base.c_str(), midiaId.c_str()); http.end(); return 2; }
    if (code != 200) {
      Serial.printf("[MIDIA] %s: midias/%s -> HTTP %d\n", base.c_str(), midiaId.c_str(), code);
      http.end();
      return 1;
    }
    JsonDocument d1;
    DeserializationError e1 = deserializeJson(d1, http.getStream());
    http.end();
    if (e1) { Serial.printf("[MIDIA] %s: JSON midias invalido: %s\n", base.c_str(), e1.c_str()); return 1; }

    arquivo = fsStr(d1["fields"]["arquivo"]);
    if (shaEsperado.length() == 0) shaEsperado = fsStr(d1["fields"]["sha256"]);
    tamanhoEsperado = fsInt(d1["fields"]["tamanho"], 0);
    if (arquivo.length() == 0) return 2;

    code = fsRequest(client, http, docUrl("arquivos_midia/" + arquivo), "GET");
    if (code == 404) { Serial.printf("[MIDIA] %s: arquivos_midia/%s nao existe (404)\n", base.c_str(), arquivo.c_str()); http.end(); return 2; }
    if (code != 200) {
      Serial.printf("[MIDIA] %s: arquivos_midia/%s -> HTTP %d\n", base.c_str(), arquivo.c_str(), code);
      http.end();
      return 1;
    }
    JsonDocument d2;
    DeserializationError e2 = deserializeJson(d2, http.getStream());
    http.end();
    if (e2) { Serial.printf("[MIDIA] %s: JSON arquivos_midia invalido: %s\n", base.c_str(), e2.c_str()); return 1; }

    totalBlocos = fsInt(d2["fields"]["total_blocos"], 1);
    if (totalBlocos <= 0) totalBlocos = 1;
    if (shaEsperado.length() == 0) shaEsperado = fsStr(d2["fields"]["sha256"]);
    if (tamanhoEsperado == 0) tamanhoEsperado = fsInt(d2["fields"]["tamanho"], 0);
  } else {
    Serial.printf("[MIDIA] %s: fast-path (%s, %d bloco(s))\n", base.c_str(), arquivo.c_str(), totalBlocos);
  }

  String ext = ".jpg";
  if (ehAudio) {
    String a = arquivo; a.toLowerCase();
    ext = a.endsWith(".wav") ? ".wav" : ".mp3";
  }

  File f;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(1000)) != pdTRUE) { Serial.println("[MIDIA] SD ocupado"); return 1; }
  for (int c = 1; c <= 3; c++) { char d[8]; snprintf(d, sizeof(d), "/cat%d", c); if (!SD.exists(d)) SD.mkdir(d); }
  if (SD.exists(ARQ_TMP_DL)) SD.remove(ARQ_TMP_DL);
  f = SD.open(ARQ_TMP_DL, FILE_WRITE);
  xSemaphoreGive(sdMutex);
  if (!f) { Serial.println("[MIDIA] Nao consegui criar /dl.tmp no SD"); return 1; }

  mbedtls_md_context_t md;
  mbedtls_md_init(&md);
  mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&md);

  size_t totalBytes = 0;
  bool ok = true;
  for (int b = 0; b < totalBlocos && ok; b++) {
    ok = baixarBloco(client, arquivo, b, f, md, totalBytes);
    if (!ok) Serial.printf("[MIDIA] Falhou no bloco %d de %d\n", b, totalBlocos);
  }

  uint8_t hash[32];
  mbedtls_md_finish(&md, hash);
  mbedtls_md_free(&md);

  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(1000)) == pdTRUE) { f.close(); xSemaphoreGive(sdMutex); }

  if (ok && tamanhoEsperado > 0 && (int)totalBytes != tamanhoEsperado) {
    Serial.printf("[MIDIA] Tamanho divergente (%u x %d)\n", (unsigned)totalBytes, tamanhoEsperado);
    ok = false;
  }
  if (ok && shaEsperado.length() == 64) {
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", hash[i]);
    shaEsperado.toLowerCase();
    if (shaEsperado != String(hex)) { Serial.println("[MIDIA] SHA-256 nao confere"); ok = false; }
  }

  if (!ok) {
    if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) == pdTRUE) { SD.remove(ARQ_TMP_DL); xSemaphoreGive(sdMutex); }
    return 1;
  }

  String destino = base + ext;
  {
    unsigned long t0 = millis();
    while (audio.isRunning() && millis() - t0 < 20000) vTaskDelay(pdMS_TO_TICKS(20));
  }
  bool trocou = false;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
    if (ehAudio) { SD.remove((base + ".mp3").c_str()); SD.remove((base + ".wav").c_str()); }
    else if (SD.exists(destino.c_str())) SD.remove(destino.c_str());
    trocou = SD.rename(ARQ_TMP_DL, destino.c_str());
    if (!trocou) SD.remove(ARQ_TMP_DL);
    xSemaphoreGive(sdMutex);
  }
  if (!trocou) { Serial.println("[MIDIA] Falha ao gravar arquivo final"); return 1; }
  Serial.printf("[MIDIA] %s gravado (%u bytes)\n", destino.c_str(), (unsigned)totalBytes);
  return 0;
}

bool existeMidia(const String& base, bool ehAudio) {
  if (!ehAudio) return sdExiste((base + ".jpg").c_str());
  return sdExiste((base + ".mp3").c_str()) || sdExiste((base + ".wav").c_str());
}

void removerMidia(const String& base, bool ehAudio) {
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    if (ehAudio) { SD.remove((base + ".mp3").c_str()); SD.remove((base + ".wav").c_str()); }
    else SD.remove((base + ".jpg").c_str());
    xSemaphoreGive(sdMutex);
  }
}

// Reconcilia 1 slot: compara "id|sha", salva manifesto a cada mudanca e so baixa o que mudou
bool reconciliarMidia(WiFiClientSecure& client, const String& uid, const String& chave,
                      const String& base, bool ehAudio, const String& idDesejado,
                      const String& shaDesejado, const String& arqHint, int blocosHint) {
  String atual = String((const char*)(manifesto[chave] | ""));
  String desejada = idDesejado + "|" + shaDesejado;
  bool existe = existeMidia(base, ehAudio);

  if (idDesejado.length() == 0) {
    if (existe) { removerMidia(base, ehAudio); houveMudancaPrancha = true; }
    if (!manifesto[chave].isNull()) { manifesto.remove(chave); salvarManifesto(); }
    return true;
  }

  // Tolerancia de migracao: se o manifesto antigo salvava so "id" (sem '|') e nao ha sha novo, aceita igual
  if (existe && (atual == desejada || (shaDesejado.length() == 0 && atual == idDesejado))) {
    return true;
  }

  if (!mostrouOledSync) {
    mostrouOledSync = true;
    mostrarMensagemOLED("SINCRONIZANDO...", "Atualizando prancha");
  }

  int r = baixarMidia(client, uid, idDesejado, ehAudio, base, shaDesejado, arqHint, blocosHint);
  Serial.printf("[SYNC] %s%s: %s\n", base.c_str(), ehAudio ? " (audio)" : " (imagem)",
                r == 0 ? "baixado" : (r == 2 ? "nao existe no servidor" : "FALHOU"));
  if (r == 0) {
    manifesto[chave] = desejada;
    salvarManifesto();
    houveMudancaPrancha = true;
    return true;
  }
  if (r == 2) {
    if (existe) { removerMidia(base, ehAudio); houveMudancaPrancha = true; }
    if (!manifesto[chave].isNull()) { manifesto.remove(chave); salvarManifesto(); }
    return true;
  }
  return false;
}

// =====================================================================
// SINCRONIZACAO DA PRANCHA (usuarios/{uid}/categorias)
// =====================================================================
struct BotaoCfg {
  bool presente = false;
  String id, rotulo;
  String imgId, imgSha, imgArq; int imgBlocos = 0;
  String audId, audSha, audArq; int audBlocos = 0;
};

struct CatCfg {
  bool presente = false;
  String nome;
  String imgId, imgSha, imgArq; int imgBlocos = 0;
  String audId, audSha, audArq; int audBlocos = 0;
  BotaoCfg b[5];
};

bool sincronizarPrancha(WiFiClientSecure& client, const String& uid) {
  if (!sdDisponivel) {
    Serial.println("[SYNC] Cartao SD ausente: adiando sincronizacao da prancha.");
    return false;
  }

  HTTPClient http;
  int code = fsRequest(client, http, docUrl("usuarios/" + uid + "/categorias"), "GET");
  if (code != 200) {
    Serial.printf("[SYNC] Categorias: HTTP %d\n", code);
    http.end();
    return false;
  }

  JsonDocument filtro;
  JsonObject ff = filtro["documents"][0]["fields"].to<JsonObject>();
  ff["ordem"]          = true;
  ff["nome"]           = true;
  ff["imagem_id"]      = true;
  ff["imagem_sha"]     = true;
  ff["imagem_arquivo"] = true;
  ff["imagem_blocos"]  = true;
  ff["audio_id"]       = true;
  ff["audio_sha"]      = true;
  ff["audio_arquivo"]  = true;
  ff["audio_blocos"]   = true;
  ff["botoes"]         = true;

  int tamEsperado = http.getSize();
  String corpo = http.getString();
  http.end();

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, corpo, DeserializationOption::Filter(filtro), DeserializationOption::NestingLimit(20));
  if (err) {
    Serial.printf("[SYNC] JSON invalido: %s (recebido=%u, esperado=%d)\n", err.c_str(), (unsigned)corpo.length(), tamEsperado);
    return false;
  }
  corpo = "";

  CatCfg cfg[3];
  JsonArray docs = doc["documents"].as<JsonArray>();
  for (JsonObject catDoc : docs) {
    JsonObject campos = catDoc["fields"];
    int ordem = fsInt(campos["ordem"], -1);
    if (ordem < 0 || ordem > 2) continue;

    CatCfg& c = cfg[ordem];
    c.presente  = true;
    c.nome      = jsStr(campos["nome"]["stringValue"], "Cat " + String(ordem + 1));
    c.imgId     = fsStr(campos["imagem_id"]);
    c.imgSha    = fsStr(campos["imagem_sha"]);
    c.imgArq    = fsStr(campos["imagem_arquivo"]);
    c.imgBlocos = fsInt(campos["imagem_blocos"], 0);
    c.audId     = fsStr(campos["audio_id"]);
    c.audSha    = fsStr(campos["audio_sha"]);
    c.audArq    = fsStr(campos["audio_arquivo"]);
    c.audBlocos = fsInt(campos["audio_blocos"], 0);

    JsonArray botoes = campos["botoes"]["arrayValue"]["values"].as<JsonArray>();
    for (JsonObject vb : botoes) {
      JsonObject bf = vb["mapValue"]["fields"];
      int ob = fsInt(bf["ordem"], -1);
      if (ob < 0 || ob > 4) continue;
      BotaoCfg& b = c.b[ob];
      b.presente  = true;
      b.id        = fsStr(bf["id"]);
      b.rotulo    = jsStr(bf["rotulo"]["stringValue"], "Botao " + String(ob + 1));
      b.imgId     = fsStr(bf["imagem_id"]);
      b.imgSha    = fsStr(bf["imagem_sha"]);
      b.imgArq    = fsStr(bf["imagem_arquivo"]);
      b.imgBlocos = fsInt(bf["imagem_blocos"], 0);
      b.audId     = fsStr(bf["audio_id"]);
      b.audSha    = fsStr(bf["audio_sha"]);
      b.audArq    = fsStr(bf["audio_arquivo"]);
      b.audBlocos = fsInt(bf["audio_blocos"], 0);
    }
  }

  int nCats = 0;
  for (int c = 0; c < 3; c++) if (cfg[c].presente) nCats++;
  Serial.printf("[SYNC] %d categoria(s) recebida(s) do servidor\n", nCats);

  // Atualiza metadados em RAM e detecta se algum nome mudou (para atualizar OLED)
  bool metaMudou = false;
  if (xSemaphoreTake(metaMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    for (int c = 0; c < 3; c++) {
      String novoNome = cfg[c].presente ? cfg[c].nome : ("Cat " + String(c + 1));
      if (pranchaMeta[c].nome != novoNome) { pranchaMeta[c].nome = novoNome; metaMudou = true; }
      for (int b = 0; b < 5; b++) {
        String novoId  = cfg[c].b[b].presente ? cfg[c].b[b].id : String("");
        String novoRot = cfg[c].b[b].presente ? cfg[c].b[b].rotulo : ("Botao " + String(b + 1));
        if (pranchaMeta[c].botoes[b].id != novoId || pranchaMeta[c].botoes[b].rotulo != novoRot) {
          pranchaMeta[c].botoes[b].id     = novoId;
          pranchaMeta[c].botoes[b].rotulo = novoRot;
          metaMudou = true;
        }
      }
    }
    xSemaphoreGive(metaMutex);
  }

  houveMudancaPrancha = false;
  mostrouOledSync = false;

  bool tudoOk = true;
  for (int c = 0; c < 3; c++) {
    String n = String(c + 1);
    String pasta = "/cat" + n;
    tudoOk &= reconciliarMidia(client, uid, "c" + n + "i", pasta + "/icone", false,
                               cfg[c].imgId, cfg[c].imgSha, cfg[c].imgArq, cfg[c].imgBlocos);
    tudoOk &= reconciliarMidia(client, uid, "c" + n + "a", pasta + "/icone", true,
                               cfg[c].audId, cfg[c].audSha, cfg[c].audArq, cfg[c].audBlocos);
    for (int b = 0; b < 5; b++) {
      String m = String(b + 1);
      String base = pasta + "/b" + m;
      tudoOk &= reconciliarMidia(client, uid, "c" + n + "b" + m + "i", base, false,
                                 cfg[c].b[b].imgId, cfg[c].b[b].imgSha, cfg[c].b[b].imgArq, cfg[c].b[b].imgBlocos);
      tudoOk &= reconciliarMidia(client, uid, "c" + n + "b" + m + "a", base, true,
                                 cfg[c].b[b].audId, cfg[c].b[b].audSha, cfg[c].b[b].audArq, cfg[c].b[b].audBlocos);
    }
  }

  if (metaMudou) salvarMetadadosPranchaNoSD();

  if (houveMudancaPrancha) {
    recarregarTelasPendente = true;
    houveMudancaPrancha = false;
  } else if (metaMudou || mostrouOledSync) {
    atualizarOLEDStatus();
  }

  Serial.printf("[SYNC] Prancha %s\n", tudoOk ? "sincronizada" : "COM FALHAS (tenta de novo)");
  return tudoOk;
}

// =====================================================================
// DISPOSITIVO: LE CONFIG, ENVIA TELEMETRIA E ACIONAMENTOS
// =====================================================================
bool dispositivoPareado = false;
int  falhasSync = 0;
unsigned long proximoSyncPermitidoMs = 0;

void descartarLogsLocais() {
  if (!sdDisponivel) return;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
    if (SD.exists(ARQ_LOG))   SD.remove(ARQ_LOG);
    if (SD.exists(ARQ_ENVIO)) SD.remove(ARQ_ENVIO);
    xSemaphoreGive(sdMutex);
  }
  if (ntpEpochSync != 0) ntpMarcadorPendente = true;
}

void esquecerSincronizacao() {
  configVersaoLocal = -1;
  falhasSync = 0;
  proximoSyncPermitidoMs = 0;
  manifesto.clear();
  salvarManifesto();
  alertaBateriaEnviado = false;
  prefs.begin("casa_cfg", false);
  prefs.putInt("cfg_ver", -1);
  prefs.putBool("bat_alert", false);
  prefs.end();
}

void desvincularLocal() {
  Serial.println("[PAREAMENTO] Aparelho desvinculado da conta.");
  ownerUid = "";
  prefs.begin("casa_cfg", false);
  prefs.remove("owner_uid");
  prefs.end();
  esquecerSincronizacao();
  descartarLogsLocais();
}

void vincularNovoDono(const String& uid) {
  Serial.println("[PAREAMENTO] Dono definido.");
  ownerUid = uid;
  prefs.begin("casa_cfg", false);
  prefs.putString("owner_uid", ownerUid);
  prefs.end();
  esquecerSincronizacao();
  descartarLogsLocais();
  forcarTelemetria = true;
}

void limparPinPendente() {
  pinPendente = "";
  prefs.begin("casa_cfg", false);
  prefs.remove("pin_pend");
  prefs.end();
}

void limparEstadoRepareamento() {
  reparPendente = false;
  reparBase = "-";
  prefs.begin("casa_cfg", false);
  prefs.remove("repar");
  prefs.remove("rep_base");
  prefs.end();
}

void garantirCodigoPareamento(WiFiClientSecure& client) {
  unsigned long agora = millis();
  if (codigoPareamento[0] != 0 && (agora - codigoGeradoMs) < PAREAMENTO_VALIDADE_MS) return;

  codigoPareamento[0] = 0;
  for (int tentativa = 0; tentativa < 3; tentativa++) {
    char cod[8];
    bool usandoPin = (tentativa == 0 && pinPendente.length() == 6);
    if (usandoPin) snprintf(cod, sizeof(cod), "%s", pinPendente.c_str());
    else           snprintf(cod, sizeof(cod), "%06lu", (unsigned long)(esp_random() % 1000000UL));

    JsonDocument doc;
    JsonObject f = doc["fields"].to<JsonObject>();
    f["mac"]["stringValue"]      = macComPontos;
    f["firmware"]["stringValue"] = String(FIRMWARE_VER);
    String corpo;
    serializeJson(doc, corpo);

    HTTPClient http;
    int code = fsRequest(client, http, docUrl("pareamentos/" + String(cod)) + "?currentDocument.exists=false",
                         "PATCH", corpo);
    http.end();

    if (usandoPin && (code == 200 || code == 409 || code == 400 || code == 403)) limparPinPendente();

    if (code == 200) {
      memcpy(codigoPareamento, cod, sizeof(cod));
      codigoGeradoMs = millis();
      Serial.println("[PAREAMENTO] Codigo publicado (veja no OLED).");
      return;
    }
    if (code == 409 || code == 400 || code == 403) continue;
    Serial.printf("[PAREAMENTO] Nao foi possivel publicar o codigo: HTTP %d\n", code);
    break;
  }
}

void tratarNaoPareado(WiFiClientSecure& client) {
  dispositivoPareado = false;
  logUrlEnviada = "";
  statusSync = SYNC_NAO_PAREADO;
  if (ownerUid.length() > 0) desvincularLocal();
  garantirCodigoPareamento(client);
  atualizarOLEDStatus();
}

// =====================================================================
// REDES WI-FI (NVS + lista vinda do site, cifrada)
// =====================================================================
void carregarRedesNVS() {
  numRedes = 0;
  prefs.begin("casa_cfg", false);
  int n = prefs.getInt("w_n", -1);
  if (n < 0) {
    String s = prefs.getString("wifi_ssid", "");
    if (s.length() > 0) { redes[0].ssid = s; redes[0].pass = prefs.getString("wifi_pass", ""); numRedes = 1; }
  } else {
    if (n > MAX_REDES) n = MAX_REDES;
    for (int i = 0; i < n; i++) {
      char ks[8], kp[8];
      snprintf(ks, sizeof(ks), "w%ds", i);
      snprintf(kp, sizeof(kp), "w%dp", i);
      String s = prefs.getString(ks, "");
      if (s.length() == 0) continue;
      redes[numRedes].ssid = s;
      redes[numRedes].pass = prefs.getString(kp, "");
      numRedes++;
    }
  }
  wifiVersaoLocal = prefs.getInt("w_ver", -1);
  temChaveWifi = (prefs.getBytesLength("wifi_key") == 32) && (prefs.getBytes("wifi_key", wifiKey, 32) == 32);
  prefs.end();

  temRedesConfiguradas = (numRedes > 0);
  if (numRedes > 0) { wifiSSID = redes[0].ssid; wifiPass = redes[0].pass; }
  wifiStatus = temChaveWifi ? "aguardando" : "sem_chave";
}

void salvarRedesNVS() {
  prefs.begin("casa_cfg", false);
  for (int i = 0; i < MAX_REDES; i++) {
    char ks[8], kp[8];
    snprintf(ks, sizeof(ks), "w%ds", i);
    snprintf(kp, sizeof(kp), "w%dp", i);
    if (i < numRedes) { prefs.putString(ks, redes[i].ssid); prefs.putString(kp, redes[i].pass); }
    else              { prefs.remove(ks); prefs.remove(kp); }
  }
  prefs.putInt("w_ver", wifiVersaoLocal);
  prefs.putInt("w_n", numRedes);
  prefs.end();
  temRedesConfiguradas = (numRedes > 0);
}

bool decifrarSenha(const String& b64, String& saida) {
  saida = "";
  if (b64.length() == 0) return true;
  if (!temChaveWifi || b64.length() > 200) return false;
  uint8_t raw[160];
  size_t olen = 0;
  if (mbedtls_base64_decode(raw, sizeof(raw), &olen, (const unsigned char*)b64.c_str(), b64.length()) != 0) return false;
  if (olen < 28) return false;
  size_t ctLen = olen - 28;
  if (ctLen > 64) return false;
  char claro[72];
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  int r = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, wifiKey, 256);
  if (r == 0) {
    r = mbedtls_gcm_auth_decrypt(&ctx, ctLen, raw, 12, NULL, 0, raw + 12 + ctLen, 16,
                                 raw + 12, (unsigned char*)claro);
  }
  mbedtls_gcm_free(&ctx);
  if (r != 0) return false;
  claro[ctLen] = 0;
  saida = String(claro);
  return true;
}

int indiceRede(RedeWifi* lista, int n, const String& ssid) {
  for (int i = 0; i < n; i++) if (lista[i].ssid == ssid) return i;
  return -1;
}

void aplicarRedesDoSite(JsonObject f) {
  if (f["wifi_versao"].isNull() || f["wifi_redes"].isNull()) return;
  int32_t vRemota = fsInt(f["wifi_versao"], -1);
  if (vRemota == wifiVersaoLocal) return;
  if (!temChaveWifi) { wifiStatus = "sem_chave"; return; }

  JsonArray vals = f["wifi_redes"]["arrayValue"]["values"].as<JsonArray>();
  RedeWifi nova[MAX_REDES];
  int n = 0;
  bool falha = false;
  for (JsonVariant v : vals) {
    if (n >= MAX_REDES_SITE) break;
    JsonObject rf = v["mapValue"]["fields"];
    String ssid = fsStr(rf["ssid"]);
    String cif  = fsStr(rf["senha_cifrada"]);
    if (ssid.length() == 0 || ssid.length() > 32) { falha = true; break; }
    if (indiceRede(nova, n, ssid) >= 0) continue;
    String senha;
    if (!decifrarSenha(cif, senha)) { falha = true; break; }
    nova[n].ssid = ssid;
    nova[n].pass = senha;
    n++;
  }
  if (falha) {
    wifiStatus = "erro_decifrar";
    Serial.println("[WIFI] Lista do site invalida/indecifravel: mantida a lista atual.");
    return;
  }
  if (n == 0) {
    wifiVersaoLocal = vRemota;
    prefs.begin("casa_cfg", false); prefs.putInt("w_ver", wifiVersaoLocal); prefs.end();
    wifiStatus = "ok";
    forcarTelemetria = true;
    return;
  }

  if (WiFi.status() == WL_CONNECTED && n < MAX_REDES) {
    String atual = WiFi.SSID();
    if (atual.length() > 0 && indiceRede(nova, n, atual) < 0) {
      int i = indiceRede(redes, numRedes, atual);
      if (i >= 0) { nova[n] = redes[i]; n++; }
    }
  }

  for (int i = 0; i < n; i++) redes[i] = nova[i];
  for (int i = n; i < MAX_REDES; i++) { redes[i].ssid = ""; redes[i].pass = ""; }
  numRedes = n;
  if (redeIdx >= numRedes) redeIdx = 0;
  wifiVersaoLocal = vRemota;
  salvarRedesNVS();
  wifiStatus = "ok";
  forcarTelemetria = true;
  Serial.printf("[WIFI] %d rede(s) aplicadas (versao %d).\n", numRedes, (int)wifiVersaoLocal);
}

// =====================================================================
// REALTIME DATABASE: flag de atualizacao (/dispositivo/controle/{MAC})
// =====================================================================
String rtdbCaminho() { return String(RTDB_RAIZ_CONTROLE) + macUrl; }

int rtdbRequest(WiFiClientSecure& client, HTTPClient& http, const char* metodo, const String& corpo = "") {
  if (!firebaseGarantirToken()) return -1;
  String url = String(RTDB_URL) + rtdbCaminho() + ".json";
  if (idToken.length() > 0 && strlen(FIREBASE_API_KEY) > 0) url += "?auth=" + idToken;
  http.setConnectTimeout(8000);
  http.setTimeout(15000);
  http.useHTTP10(true);
  if (!http.begin(client, url)) return -1;
  if (corpo.length() > 0) http.addHeader("Content-Type", "application/json");
  int code = http.sendRequest(metodo, corpo);
  if (code == 401) { idToken = ""; tokenExpiraMs = 0; }
  return code;
}

bool lerGatilhoRtdb(WiFiClientSecure& client, bool& atualizar, String& ts) {
  HTTPClient http;
  int code = rtdbRequest(client, http, "GET");
  if (code != 200) {
    Serial.printf("[RTDB] Leitura de %s: HTTP %d\n", rtdbCaminho().c_str(), code);
    http.end();
    return false;
  }
  String corpo = http.getString();
  http.end();
  JsonDocument doc;
  if (deserializeJson(doc, corpo) != DeserializationError::Ok) return false;
  atualizar = doc["atualizar"] | false;
  ts = "";
  if (!doc["timestamp"].isNull()) serializeJson(doc["timestamp"], ts);
  return true;
}

bool limparGatilhoRtdb(WiFiClientSecure& client) {
  HTTPClient http;
  int code = rtdbRequest(client, http, "PATCH", "{\"atualizar\":false}");
  http.end();
  if (code != 200) Serial.printf("[RTDB] Nao consegui zerar a flag: HTTP %d\n", code);
  return code == 200;
}

void registrarFalhaSync() {
  falhasSync++;
  unsigned long espera = min(30000UL << min(falhasSync - 1, 4), 300000UL);
  proximoSyncPermitidoMs = millis() + espera;
}

WiFiClientSecure* rtdbStream = nullptr;
String   rtdbLinha = "", rtdbEventoAtual = "";
bool     rtdbAtualizar = false;
String   rtdbTs = "";
volatile bool rtdbGatilho = false;
bool     rtdbFecharPedido = false;
unsigned long rtdbUltimoByteMs = 0, rtdbProxTentativaMs = 0, rtdbEsperaMs = 5000;

void rtdbFecharStream() {
  if (rtdbStream) { rtdbStream->stop(); delete rtdbStream; rtdbStream = nullptr; }
  rtdbLinha = ""; rtdbEventoAtual = ""; rtdbFecharPedido = false;
}

bool rtdbLerLinhaHttp(WiFiClientSecure& c, String& out, unsigned long timeoutMs) {
  out = "";
  unsigned long t0 = millis();
  while (millis() - t0 < timeoutMs) {
    while (c.available()) {
      int ch = c.read();
      if (ch == '\n') return true;
      if (ch != '\r' && out.length() < 200) out += (char)ch;
    }
    if (!c.connected()) return false;
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  return false;
}

bool rtdbAbrirStream() {
  if (!firebaseGarantirToken()) return false;
  String host = String(RTDB_URL);
  host.replace("https://", "");
  while (host.endsWith("/")) host.remove(host.length() - 1);

  rtdbStream = new WiFiClientSecure();
  rtdbStream->setInsecure();
  if (!rtdbStream->connect(host.c_str(), 443, 8000)) {
    Serial.println("[RTDB] Nao consegui conectar no Realtime Database");
    rtdbFecharStream();
    return false;
  }
  String req = "GET " + rtdbCaminho() + ".json";
  if (idToken.length() > 0 && strlen(FIREBASE_API_KEY) > 0) req += "?auth=" + idToken;
  req += " HTTP/1.1\r\nHost: " + host + "\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
  rtdbStream->print(req);

  String linha;
  if (!rtdbLerLinhaHttp(*rtdbStream, linha, 8000) || !linha.startsWith("HTTP/1.") || linha.indexOf(" 200") < 0) {
    Serial.printf("[RTDB] Stream recusado: '%s'\n", linha.c_str());
    if (linha.indexOf(" 401") >= 0) { idToken = ""; tokenExpiraMs = 0; }
    rtdbFecharStream();
    return false;
  }
  for (;;) {
    if (!rtdbLerLinhaHttp(*rtdbStream, linha, 5000)) { rtdbFecharStream(); return false; }
    if (linha.length() == 0) break;
  }
  rtdbUltimoByteMs = millis();
  rtdbAtualizar = false;
  rtdbTs = "";
  Serial.println("[RTDB] Escutando " + rtdbCaminho() + " (sem polling)");
  return true;
}

void rtdbTratarLinha(const String& l) {
  if (l.startsWith("event:")) {
    rtdbEventoAtual = l.substring(6); rtdbEventoAtual.trim();
    if (rtdbEventoAtual == "cancel" || rtdbEventoAtual == "auth_revoked") {
      Serial.printf("[RTDB] Stream encerrado (%s): reconectando\n", rtdbEventoAtual.c_str());
      idToken = ""; tokenExpiraMs = 0;
      rtdbFecharPedido = true;
    }
    return;
  }
  if (!l.startsWith("data:")) return;
  if (rtdbEventoAtual != "put" && rtdbEventoAtual != "patch") return;

  JsonDocument d;
  if (deserializeJson(d, l.substring(5)) != DeserializationError::Ok) return;
  String path = d["path"] | "/";
  JsonVariant dado = d["data"];
  if (path == "/") {
    if (rtdbEventoAtual == "put") { rtdbAtualizar = false; rtdbTs = ""; }
    if (dado.is<JsonObject>()) {
      if (!dado["atualizar"].isNull()) rtdbAtualizar = dado["atualizar"].as<bool>();
      if (!dado["timestamp"].isNull()) { rtdbTs = ""; serializeJson(dado["timestamp"], rtdbTs); }
    }
  } else if (path == "/atualizar") {
    rtdbAtualizar = dado.as<bool>();
  } else if (path == "/timestamp") {
    rtdbTs = ""; if (!dado.isNull()) serializeJson(dado, rtdbTs);
  }
  if (rtdbAtualizar) rtdbGatilho = true;
}

void rtdbProcessarStream() {
  if (!rtdbStream) return;
  while (rtdbStream && rtdbStream->available()) {
    int c = rtdbStream->read();
    if (c < 0) break;
    rtdbUltimoByteMs = millis();
    if (c == '\r') continue;
    if (c == '\n') { rtdbTratarLinha(rtdbLinha); rtdbLinha = ""; }
    else if (rtdbLinha.length() < 512) rtdbLinha += (char)c;
    if (rtdbFecharPedido) break;
  }
  bool morreu = rtdbFecharPedido || !rtdbStream->connected() ||
                (millis() - rtdbUltimoByteMs > 90000UL);
  if (morreu) {
    if (!rtdbFecharPedido) Serial.println("[RTDB] Conexao perdida: reconectando");
    rtdbFecharStream();
    rtdbProxTentativaMs = millis() + 2000;
  }
}

void sincronizarConfig(WiFiClientSecure& client) {
  HTTPClient http;
  int code = fsRequest(client, http, docUrl("dispositivos/" + macUrl), "GET");

  if (code == 404) {
    http.end();
    if (reparPendente) limparEstadoRepareamento();   // nada antigo a ignorar
    tratarNaoPareado(client);
    return;
  }
  if (code == 401 || code == 403) {
    String corpoErro = http.getString();
    http.end();
    statusSync = SYNC_ERRO_ACESSO;
    Serial.printf("[SYNC] HTTP %d: %s\n", code, corpoErro.substring(0, 300).c_str());
    return;
  }
  if (code != 200) { http.end(); statusSync = SYNC_ERRO; return; }

  int tamEsperado = http.getSize();
  String corpo = http.getString();
  http.end();
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, corpo, DeserializationOption::NestingLimit(20));
  if (err) {
    statusSync = SYNC_ERRO;
    Serial.printf("[SYNC] Dispositivo: JSON invalido: %s (recebido=%u, esperado=%d)\n", err.c_str(), (unsigned)corpo.length(), tamEsperado);
    return;
  }
  corpo = "";

  JsonObject f = doc["fields"];
  String uid = fsStr(f["owner_uid"]);
  if (uid.length() == 0) uid = fsStr(f["idUsuarioDono"]);
  if (uid.length() == 0) {
    if (reparPendente) limparEstadoRepareamento();
    tratarNaoPareado(client);
    return;
  }

  // Handshake de re-pareamento apos BLE: ignora o documento antigo ate o app gravar novo pareado_em (ou novo dono)
  if (reparPendente) {
    String marca = fsStr(f["pareado_em"]);
    if (marca.length() == 0) marca = uid + "|" + fsStr(f["criado_em"]);
    if (reparBase == "-") {
      reparBase = marca;
      prefs.begin("casa_cfg", false);
      prefs.putString("rep_base", reparBase);
      prefs.end();
    }
    if (marca == reparBase) {
      tratarNaoPareado(client);
      return;
    }
    Serial.println("[PAREAMENTO] Novo vinculo confirmado apos BLE.");
    limparEstadoRepareamento();
  }

  bool eraPareado = dispositivoPareado;
  dispositivoPareado = true;
  statusSync = SYNC_OK;
  codigoPareamento[0] = 0;
  if (!eraPareado) forcarTelemetria = true;

  if (uid != ownerUid) vincularNovoDono(uid);

  if (!eraPareado) {
    iniciarVibracao(200);
    atualizarOLEDStatus();
  }

  if (xSemaphoreTake(metaMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
    modoContexto = jsStr(f["modo"]["stringValue"], "casa");
    xSemaphoreGive(metaMutex);
  }

  if (!f["volume"].isNull()) {
    int volPct = constrain(fsInt(f["volume"], 70), 0, 100);
    volumePendente = map(volPct, 0, 100, 0, VOLUME_MAXIMO);
  }

  aplicarRedesDoSite(f);
}

bool sincronizarTudo(WiFiClientSecure& client) {
  sincronizarConfig(client);
  if (statusSync != SYNC_OK) return false;
  return sincronizarPrancha(client, ownerUid);
}

bool executarVarredura(WiFiClientSecure& client, bool viaGatilho) {
  String tsInicio = rtdbTs;
  if (viaGatilho) Serial.printf("[RTDB] atualizar=true (timestamp %s): varrendo o Firestore\n", tsInicio.c_str());

  bool ok = sincronizarTudo(client);
  if (statusSync == SYNC_NAO_PAREADO) {
    rtdbGatilho = false;
    return true;
  }
  if (!ok) { registrarFalhaSync(); return false; }
  falhasSync = 0;
  configVersaoLocal = 0;
  prefs.begin("casa_cfg", false); prefs.putInt("cfg_ver", configVersaoLocal); prefs.end();

  if (viaGatilho) {
    bool atualizar = false;
    String tsAgora;
    if (!lerGatilhoRtdb(client, atualizar, tsAgora)) { registrarFalhaSync(); return false; }
    if (atualizar && tsAgora != tsInicio) {
      Serial.println("[RTDB] Novo pedido chegou durante o download: flag mantida.");
    } else if (!limparGatilhoRtdb(client)) {
      registrarFalhaSync();
      return false;
    } else {
      Serial.println("[RTDB] Aparelho atualizado: atualizar=false gravado.");
    }
  }
  rtdbGatilho = false;
  return true;
}

void enviarNotificacaoBateriaBaixa(WiFiClientSecure& client, int batPct) {
  if (!dispositivoPareado || ownerUid.length() == 0 || alertaBateriaEnviado) return;

  char id[16];
  snprintf(id, sizeof(id), "%08x%04x", (unsigned)esp_random(), (unsigned)(esp_random() & 0xFFFF));

  JsonDocument doc;
  JsonObject f = doc["fields"].to<JsonObject>();
  f["tipo"]["stringValue"]     = "bateria_baixa";
  f["titulo"]["stringValue"]   = "Bateria do aparelho baixa";
  f["mensagem"]["stringValue"] = "O dispositivo C.A.S.A. esta com " + String(batPct) + "% de bateria.";
  f["lida"]["booleanValue"]    = false;
  if (relogioValido()) f["criada_em"]["stringValue"] = isoDeEpoch((uint32_t)time(nullptr));
  String corpo;
  serializeJson(doc, corpo);

  HTTPClient http;
  int code = fsRequest(client, http, docUrl("usuarios/" + ownerUid + "/notificacoes/" + String(id)), "PATCH", corpo);
  http.end();
  if (code == 200) {
    alertaBateriaEnviado = true;
    prefs.begin("casa_cfg", false);
    prefs.putBool("bat_alert", true);
    prefs.end();
  }
}

void enviarTelemetria(WiFiClientSecure& client) {
  if (!dispositivoPareado) return;

  float bat = obterBateriaThreadSafe();
  int batInt = (bat >= 0.0f) ? (int)round(bat) : -1;
  int sinal = calcularQualidadeWifiPct();

  JsonDocument doc;
  JsonObject f = doc["fields"].to<JsonObject>();
  String mascara = "currentDocument.exists=true";
  auto campo = [&](const char* nome) { mascara += "&updateMask.fieldPaths="; mascara += nome; };

  if (batInt >= 0) {
    f["bateria_pct"]["integerValue"]  = String(batInt);
    f["nivelBateria"]["integerValue"] = String(batInt);
    campo("bateria_pct"); campo("nivelBateria");
  }
  f["ip"]["stringValue"]         = WiFi.localIP().toString();
  f["firmware"]["stringValue"]   = String(FIRMWARE_VER);
  f["ssid"]["stringValue"]       = WiFi.SSID();
  f["wifi_versao_aplicada"]["integerValue"] = String((int)wifiVersaoLocal);
  f["wifi_status"]["stringValue"] = wifiStatus;
  f["sinal_wifi"]["integerValue"] = String(sinal);
  f["statusOnline"]["booleanValue"] = true;
  campo("ip"); campo("firmware"); campo("ssid"); campo("sinal_wifi"); campo("statusOnline");
  campo("wifi_versao_aplicada"); campo("wifi_status");
  if (relogioValido()) {
    f["ultima_sincronizacao"]["stringValue"] = isoDeEpoch((uint32_t)time(nullptr));
    campo("ultima_sincronizacao");
  }

  String corpo;
  serializeJson(doc, corpo);
  HTTPClient http;
  int code = fsRequest(client, http, docUrl("dispositivos/" + macUrl) + "?" + mascara, "PATCH", corpo);
  http.end();
  if (code != 200) Serial.printf("[TELEMETRIA] HTTP %d\n", code);

  if (batInt >= 0) {
    if (batInt <= 20) enviarNotificacaoBateriaBaixa(client, batInt);
    else if (batInt >= 30 && alertaBateriaEnviado) {
      alertaBateriaEnviado = false;
      prefs.begin("casa_cfg", false);
      prefs.putBool("bat_alert", false);
      prefs.end();
    }
  }
}

void enviarLogUrl(WiFiClientSecure& client) {
#if LOG_SERVER_ATIVO
  if (!dispositivoPareado || !logServerNoAr || WiFi.status() != WL_CONNECTED) return;
  if ((long)(millis() - proxLogUrlMs) < 0) return;

  String url = "http://" + WiFi.localIP().toString();
  if (url == logUrlEnviada) return;

  JsonDocument doc;
  doc["fields"]["log_url"]["stringValue"] = url;
  String corpo;
  serializeJson(doc, corpo);

  HTTPClient http;
  int code = fsRequest(client, http,
                       docUrl("dispositivos/" + macUrl) + "?currentDocument.exists=true&updateMask.fieldPaths=log_url",
                       "PATCH", corpo);
  http.end();
  if (code == 200) {
    logUrlEnviada = url;
    Serial.printf("[LOGS] Endereco publicado no painel: %s\n", url.c_str());
  } else {
    proxLogUrlMs = millis() + 300000UL;
  }
#endif
}

// ---- Acionamentos ----
struct MarcadorSync { uint32_t boot, uptime, epoch; };

bool lerLinhaSD(File& f, String& linha) {
  bool ok = false;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    if (f.available()) { linha = f.readStringUntil('\n'); linha.trim(); ok = true; }
    xSemaphoreGive(sdMutex);
  }
  return ok;
}

int dividirCampos(const String& s, String* out, int max) {
  int n = 0, ini = 0;
  while (n < max - 1) {
    int p = s.indexOf(',', ini);
    if (p < 0) break;
    out[n++] = s.substring(ini, p);
    ini = p + 1;
  }
  out[n++] = s.substring(ini);
  return n;
}

bool enviarLoteAcionamentos(WiFiClientSecure& client, JsonDocument& doc) {
  String corpo;
  serializeJson(doc, corpo);
  HTTPClient http;
  String url = "https://firestore.googleapis.com/v1/projects/" + String(PROJECT_ID) +
               "/databases/(default)/documents:commit";
  int code = fsRequest(client, http, url, "POST", corpo);
  http.end();
  if (code == 200) return true;
  if (code == 400) {
    Serial.println("[LOG] Lote rejeitado (400), descartado.");
    return true;
  }
  Serial.printf("[LOG] Envio falhou: HTTP %d\n", code);
  return false;
}

void enviarAcionamentos(WiFiClientSecure& client) {
  if (!dispositivoPareado || ownerUid.length() == 0 || !sdDisponivel) return;
  if (ntpMarcadorPendente || !relogioValido()) return;

  bool temLote = false;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(300)) == pdTRUE) {
    if (SD.exists(ARQ_ENVIO)) {
      temLote = true;
    } else if (SD.exists(ARQ_LOG)) {
      File t = SD.open(ARQ_LOG, FILE_READ);
      size_t tam = t ? t.size() : 0;
      if (t) t.close();
      if (tam > 0 && SD.rename(ARQ_LOG, ARQ_ENVIO)) temLote = true;
    }
    xSemaphoreGive(sdMutex);
  }
  if (!temLote) return;

  std::vector<MarcadorSync> marcadores;
  {
    File f;
    if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) != pdTRUE) return;
    f = SD.open(ARQ_ENVIO, FILE_READ);
    xSemaphoreGive(sdMutex);
    if (!f) return;
    String linha;
    while (lerLinhaSD(f, linha)) {
      if (!linha.startsWith("#SYNC,")) continue;
      String c[4];
      if (dividirCampos(linha, c, 4) == 4) {
        marcadores.push_back({ (uint32_t)strtoul(c[1].c_str(), NULL, 10),
                               (uint32_t)strtoul(c[2].c_str(), NULL, 10),
                               (uint32_t)strtoul(c[3].c_str(), NULL, 10) });
      }
    }
    if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) == pdTRUE) { f.close(); xSemaphoreGive(sdMutex); }
  }

  File f;
  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) != pdTRUE) return;
  f = SD.open(ARQ_ENVIO, FILE_READ);
  xSemaphoreGive(sdMutex);
  if (!f) return;

  const String baseDoc = "projects/" + String(PROJECT_ID) + "/databases/(default)/documents/usuarios/" + ownerUid + "/acionamentos/";
  JsonDocument lote;
  JsonArray escritas = lote["writes"].to<JsonArray>();
  bool tudoOk = true;
  String linha;

  while (tudoOk && lerLinhaSD(f, linha)) {
    if (linha.length() == 0 || linha.startsWith("#")) continue;

    String c[8];
    if (dividirCampos(linha, c, 8) < 8) continue;

    String chave = c[0];
    bool tsEpoch = (c[1] == "E");
    uint32_t ts = (uint32_t)strtoul(c[2].c_str(), NULL, 10);
    int cat = c[3].toInt(), btn = c[4].toInt();
    uint32_t bootDoEvento = (uint32_t)strtoul(chave.c_str(), NULL, 10);

    uint32_t epoch = 0;
    bool aproximado = false;
    if (tsEpoch) {
      epoch = ts;
    } else {
      bool achou = false;
      for (const MarcadorSync& m : marcadores) {
        if (m.boot == bootDoEvento) {
          epoch = (ts <= m.uptime) ? m.epoch - (m.uptime - ts) : m.epoch + (ts - m.uptime);
          achou = true;
          break;
        }
      }
      if (!achou) {
        aproximado = true;
        uint32_t agora = (uint32_t)time(nullptr);
        epoch = (bootDoEvento == bootCount && ts <= millis() / 1000) ? agora - (millis() / 1000 - ts) : agora;
      }
    }

    JsonObject w = escritas.add<JsonObject>();
    JsonObject u = w["update"].to<JsonObject>();
    u["name"] = baseDoc + macSemPontos + "_" + chave;
    JsonObject fl = u["fields"].to<JsonObject>();
    fl["botao_id"]["stringValue"]       = (c[5].length() > 0) ? c[5] : ("b" + String(btn));
    fl["botao_nome"]["stringValue"]     = (c[7].length() > 0) ? c[7] : ("Botao " + String(btn));
    fl["categoria_nome"]["stringValue"] = (c[6].length() > 0) ? c[6] : ("Cat " + String(cat));
    fl["dispositivo"]["stringValue"]    = macComPontos;
    fl["origem"]["stringValue"]         = "dispositivo";
    fl["acionado_em"]["stringValue"]    = isoDeEpoch(epoch);
    if (aproximado) fl["tempo_aproximado"]["booleanValue"] = true;

    if (escritas.size() >= 20) {
      tudoOk = enviarLoteAcionamentos(client, lote);
      lote.clear();
      escritas = lote["writes"].to<JsonArray>();
    }
  }
  if (tudoOk && escritas.size() > 0) tudoOk = enviarLoteAcionamentos(client, lote);

  if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    f.close();
    if (tudoOk) SD.remove(ARQ_ENVIO);
    xSemaphoreGive(sdMutex);
  }
  if (tudoOk) Serial.println("[LOG] Acionamentos sincronizados.");
}

// =====================================================================
// BLE
// =====================================================================
bool jsonCompletoValido(const String& s) {
  int nivel = 0;
  bool dentroDeAspas = false, viuAbertura = false;
  for (int i = 0; i < (int)s.length(); i++) {
    char c = s[i];
    if (dentroDeAspas && c == '\\') { i++; continue; }
    if (c == '"') dentroDeAspas = !dentroDeAspas;
    else if (!dentroDeAspas) {
      if (c == '{') { nivel++; viuAbertura = true; }
      else if (c == '}') { nivel--; if (viuAbertura && nivel == 0) return true; }
    }
  }
  return false;
}

void gerarPinBle() {
  snprintf(blePin, sizeof(blePin), "%06lu", (unsigned long)(esp_random() % 1000000UL));
  blePinFalhas = 0;
}

void mostrarTelaConfigBle() {
  if (!oledOk) return;
  char l1[28];
  snprintf(l1, sizeof(l1), "%s PIN do app", nomeBleAtual.c_str());
  if (xSemaphoreTake(i2cMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    oledCodigoGrande(l1, blePin);
    xSemaphoreGive(i2cMutex);
  }
}

void definirStatusBle(const char* st) {
  if (pBleStatus) pBleStatus->setValue(st);
}

class BLEServerCallbacksCustom : public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) { bleBufferAcumulado = ""; }
  void onDisconnect(BLEServer* pServer) {
    bleBufferAcumulado = "";
    BLEDevice::startAdvertising();
  }
};

class BLEConfigCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* pCharacteristic) {
    String chunk = pCharacteristic->getValue().c_str();
    bleBufferAcumulado += chunk;
    if (bleBufferAcumulado.length() > 1024) { bleBufferAcumulado = ""; return; }
    if (!jsonCompletoValido(bleBufferAcumulado)) return;

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, bleBufferAcumulado);
    bleBufferAcumulado = "";
    if (err) { definirStatusBle("json_invalido"); return; }

    if (millis() < bleBloqueadoAteMs) { definirStatusBle("bloqueado"); return; }
    String pinRecebido = jsStr(doc["pin"], "");
    if (pinRecebido != String(blePin)) {
      blePinFalhas = blePinFalhas + 1;
      Serial.println("[BLE] PIN incorreto.");
      if (blePinFalhas >= 3) {
        bleBloqueadoAteMs = millis() + 10000UL;
        blePinRenovar = true;
        definirStatusBle("bloqueado");
      } else {
        definirStatusBle("pin_errado");
      }
      return;
    }

    String ssid = jsStr(doc["ssid"], "");
    String pass = jsStr(doc["pass"], "");
    if (ssid.length() == 0 || ssid.length() > 32 || pass.length() > 63) { definirStatusBle("dados_invalidos"); return; }

    String chaveB64 = jsStr(doc["key"], "");
    uint8_t chave[48];
    bool trocaChave = false;
    if (chaveB64.length() > 0) {
      size_t olen = 0;
      if (chaveB64.length() > 64 ||
          mbedtls_base64_decode(chave, sizeof(chave), &olen, (const unsigned char*)chaveB64.c_str(), chaveB64.length()) != 0 ||
          olen != 32) {
        Serial.println("[BLE] Chave invalida: configuracao descartada.");
        definirStatusBle("chave_invalida");
        return;
      }
      trocaChave = true;
    }

    redes[0].ssid = ssid;
    redes[0].pass = pass;
    numRedes = 1;
    wifiVersaoLocal = -1;
    salvarRedesNVS();

    prefs.begin("casa_cfg", false);
    if (trocaChave) prefs.putBytes("wifi_key", chave, 32);
    prefs.putString("pin_pend", String(blePin));
    // Marca re-pareamento pendente: ignora o documento antigo de dispositivos/{MAC} ate o app regravar
    prefs.putBool("repar", true);
    prefs.putString("rep_base", "-");
    prefs.end();

    Serial.println("[BLE] Configuracao gravada na NVS (re-pareamento ativado).");
    definirStatusBle("ok");
    bleRecebeuConfig = true;
  }
};

// =====================================================================
// TASK DE REDE (Core 0)
// =====================================================================
// Scan passivo (nao transmite probe requests -> menor pico de corrente)
// Preenche visivel[i] = true se redes[i].ssid foi detectado no ar.
int escanearRedesConhecidas(bool visivel[MAX_REDES]) {
  for (int i = 0; i < MAX_REDES; i++) visivel[i] = false;
  int n = WiFi.scanNetworks(false, false, true, 300);
  int achadas = 0;
  if (n > 0) {
    for (int j = 0; j < n; j++) {
      String s = WiFi.SSID(j);
      for (int i = 0; i < numRedes; i++) {
        if (!visivel[i] && redes[i].ssid == s) {
          visivel[i] = true;
          achadas++;
        }
      }
    }
  }
  WiFi.scanDelete();
  return achadas;
}

void taskSincronizacaoNuvem(void* pvParameters) {
  bool ntpConfigurado = false, ntpMarcado = false;
  unsigned long esperaWifi = WIFI_ESPERA_MIN_MS;
  bool tentando = false, estavaConectado = false;
  bool scanFeitoNoCiclo = false;
  bool redeVisivel[MAX_REDES] = { false };
  unsigned long inicioTentativa = 0, proximaTentativaMs = millis();

  if (numRedes > 0) {
    WiFi.persistent(false);
    WiFi.setAutoReconnect(false);
    WiFi.mode(WIFI_STA);
    WiFi.setTxPower(WIFI_TX_POWER);
    WiFi.setSleep(true);
  }

  unsigned long ultimoStatusOLED = 0;
  unsigned long ultimaTelemetria = 0, ultimoLog = 0, ultimoPareamento = 0;
  bool varreduraInicialFeita = false;
  bool primeiraTelemetria = true;

  for (;;) {
    if (numRedes > 0) {
      if (WiFi.status() == WL_CONNECTED) {
        esperaWifi = WIFI_ESPERA_MIN_MS;
        tentando = false;
        scanFeitoNoCiclo = false;
        estavaConectado = true;

        if (!ntpConfigurado) {
          configTime(0, 0, "pool.ntp.org", "time.nist.gov");
          ntpConfigurado = true;
        }
        if (!ntpMarcado && relogioValido()) {
          ntpMarcado = true;
          ntpEpochSync  = (uint32_t)time(nullptr);
          ntpUptimeSync = millis() / 1000;
          ntpMarcadorPendente = true;
        }

        unsigned long agora = millis();
        bool esperaOk = (long)(agora - proximoSyncPermitidoMs) >= 0;
        bool deveInicial = !varreduraInicialFeita && esperaOk;
        bool deveGatilho = rtdbGatilho && esperaOk;
        bool devePareamento = !dispositivoPareado && varreduraInicialFeita && PAREAMENTO_POLL_MS > 0 &&
                              (agora - ultimoPareamento >= PAREAMENTO_POLL_MS);
        bool deveTele = dispositivoPareado && (primeiraTelemetria || forcarTelemetria ||
                              (agora - ultimaTelemetria >= INTERVALO_TELEMETRIA_MS));
        bool deveLog  = dispositivoPareado && (agora - ultimoLog >= INTERVALO_LOG_MS) &&
                        (sdExiste(ARQ_LOG) || sdExiste(ARQ_ENVIO));
        bool precisaSync = deveInicial || deveGatilho || devePareamento;

        if (precisaSync || deveTele || deveLog) {
          if (precisaSync || ESP.getFreeHeap() < HEAP_MINIMO_TLS) rtdbFecharStream();
          if (heapSuficienteParaTLS()) {
            WiFiClientSecure client;
            client.setInsecure();
            if (precisaSync) {
              if (devePareamento) ultimoPareamento = agora;
              bool ok = executarVarredura(client, deveGatilho);
              if (deveInicial) varreduraInicialFeita = ok;
            }
            if (deveTele) { ultimaTelemetria = agora; primeiraTelemetria = false; forcarTelemetria = false; enviarTelemetria(client); }
            if (deveLog)  { ultimoLog = agora; enviarAcionamentos(client); }
            enviarLogUrl(client);
          }
        }

        if (varreduraInicialFeita) {
          if (!rtdbStream && (long)(millis() - rtdbProxTentativaMs) >= 0 && heapSuficienteParaTLS()) {
            if (rtdbAbrirStream()) rtdbEsperaMs = 5000;
            else { rtdbProxTentativaMs = millis() + rtdbEsperaMs; rtdbEsperaMs = min(rtdbEsperaMs * 2, 60000UL); }
          }
          rtdbProcessarStream();
        }
      } else {
        unsigned long agoraW = millis();
        if (estavaConectado) {
          rtdbFecharStream();
          WiFi.setSleep(true);
          estavaConectado = false;
          tentando = false;
          scanFeitoNoCiclo = false;
          redeIdx = 0;
          proximaTentativaMs = agoraW;
        }
        if (!tentando) {
          if ((long)(agoraW - proximaTentativaMs) >= 0) {
            bool podeTentarAgora = true;
            if (!scanFeitoNoCiclo) {
              WiFi.disconnect(false, false);
              int achadas = escanearRedesConhecidas(redeVisivel);
              redeIdx = 0;
              if (achadas == 0) {
                Serial.printf("[WIFI] Nenhuma rede conhecida no alcance. Nova busca em %lu s.\n", esperaWifi / 1000UL);
                WiFi.setSleep(true);
                scanFeitoNoCiclo = false;
                proximaTentativaMs = millis() + esperaWifi;
                esperaWifi = min(esperaWifi * 2, WIFI_ESPERA_MAX_MS);
                podeTentarAgora = false;
              } else {
                scanFeitoNoCiclo = true;
              }
            }

            if (podeTentarAgora) {
              while (redeIdx < numRedes && !redeVisivel[redeIdx]) redeIdx++;

              if (redeIdx >= numRedes) {
                scanFeitoNoCiclo = false;
                redeIdx = 0;
                WiFi.disconnect(false, false);
                WiFi.setSleep(true);
                proximaTentativaMs = millis() + esperaWifi;
                esperaWifi = min(esperaWifi * 2, WIFI_ESPERA_MAX_MS);
              } else {
                wifiSSID = redes[redeIdx].ssid;
                wifiPass = redes[redeIdx].pass;
                Serial.printf("[WIFI] Conectando rede %d/%d: %s\n", redeIdx + 1, numRedes, wifiSSID.c_str());
                WiFi.disconnect(false, false);
                WiFi.begin(wifiSSID.c_str(), wifiPass.c_str());
                tentando = true;
                inicioTentativa = millis();
              }
            }
          }
        } else if (agoraW - inicioTentativa >= WIFI_TENTATIVA_MS) {
          tentando = false;
          redeIdx++;
          proximaTentativaMs = agoraW;
        }
      }
    }

    if (!audio.isRunning() && (millis() - ultimoStatusOLED >= 15000)) {
      ultimoStatusOLED = millis();
      atualizarOLEDStatus();
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

// =====================================================================
// SERVIDOR DE LOGS (Core 0)
// =====================================================================
#if LOG_SERVER_ATIVO
static const char PAGINA_LOGS[] PROGMEM =
  "<!DOCTYPE html><html><head><meta charset='utf-8'>"
  "<meta name='viewport' content='width=device-width,initial-scale=1'>"
  "<title>Logs C.A.S.A.</title>"
  "<style>body{background:#111;color:#0f0;font-family:monospace;padding:12px}"
  "pre{white-space:pre-wrap;word-wrap:break-word;font-size:13px}</style></head><body>"
  "<h3>PROJETO C.A.S.A. - logs ao vivo</h3><pre id='o'></pre>"
  "<script>"
  "function a(){fetch('/logs').then(r=>r.text()).then(t=>{"
  "var p=window.innerHeight+window.scrollY>=document.body.offsetHeight-40;"
  "document.getElementById('o').textContent=t;"
  "if(p)window.scrollTo(0,document.body.scrollHeight);}).catch(()=>{});}"
  "a();setInterval(a,1500);</script></body></html>";

static WebServer servidorWeb(LOG_PORTA_HTTP);
static WiFiServer servidorTelnet(LOG_PORTA_TELNET);
static WiFiClient clienteTelnet;

static void handleLogsRoot() { servidorWeb.send_P(200, "text/html", PAGINA_LOGS); }

static void handleLogsTexto() {
  String r;
  r.reserve(LOG_RING_TAM + 16);
  uint32_t cursor = 0;
  char tmp[512];
  size_t n;
  while ((n = logLer(cursor, tmp, sizeof(tmp))) > 0) r.concat(tmp, n);
  servidorWeb.sendHeader("Cache-Control", "no-store");
  servidorWeb.send(200, "text/plain; charset=utf-8", r);
}

void taskLogServer(void* pvParameters) {
  servidorWeb.on("/", handleLogsRoot);
  servidorWeb.on("/logs", handleLogsTexto);

  bool jaIniciou = false, estavaConectado = false;
  uint32_t cursorTelnet = 0;

  for (;;) {
    bool conectado = (WiFi.status() == WL_CONNECTED);
    if (!conectado) {
      if (estavaConectado) {
        WiFi.setSleep(true);
        logServerNoAr = false;
        estavaConectado = false;
      }
      vTaskDelay(pdMS_TO_TICKS(1000));
      continue;
    }

    if (!estavaConectado) {
      if (jaIniciou) { servidorWeb.stop(); servidorTelnet.stop(); }
      WiFi.setSleep(false);
      servidorWeb.begin();
      servidorTelnet.begin();
      servidorTelnet.setNoDelay(true);
      jaIniciou = true;
      estavaConectado = true;
      logServerNoAr = true;
      String ip = WiFi.localIP().toString();
      Serial.printf("[LOGS] No ar: http://%s | telnet %s porta %d\n", ip.c_str(), ip.c_str(), LOG_PORTA_TELNET);
    }

    servidorWeb.handleClient();

    if (servidorTelnet.hasClient()) {
      WiFiClient novo = servidorTelnet.available();
      if (!clienteTelnet || !clienteTelnet.connected()) {
        clienteTelnet = novo;
        cursorTelnet = 0;
      } else {
        novo.stop();
      }
    }
    if (clienteTelnet && clienteTelnet.connected()) {
      while (clienteTelnet.available()) clienteTelnet.read();
      char tmp[256];
      size_t n = logLer(cursorTelnet, tmp, sizeof(tmp));
      if (n > 0) clienteTelnet.write((const uint8_t*)tmp, n);
    }

    vTaskDelay(pdMS_TO_TICKS(5));
  }
}
#endif

// =====================================================================
// SETUP
// =====================================================================
void setup() {
  Serial.begin(115200);
  delay(800);

  const char* motivoReset = nomeMotivoReset(esp_reset_reason());
  inicializarMacStrings();
  Serial.printf("\n[C.A.S.A.] Firmware %s | MAC %s | Reset anterior: %s\n",
                FIRMWARE_VER, macComPontos.c_str(), motivoReset);

  sdMutex   = xSemaphoreCreateMutex();
  i2cMutex  = xSemaphoreCreateMutex();
  metaMutex = xSemaphoreCreateMutex();
  vibracaoTimer = xTimerCreate("VibTimer", pdMS_TO_TICKS(90), pdFALSE, (void*)0, callbackDesligarVibracao);

  for (int i = 0; i < 8; i++) pinMode(BTN_PINS[i], INPUT_PULLUP);
  pinMode(MOTOR_VIBR, OUTPUT);
  digitalWrite(MOTOR_VIBR, LOW);

  // 1. I2C / OLED
  Wire.begin(I2C_SDA, I2C_SCL, 100000);
  Wire.setTimeOut(50);
  oledOk = oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  if (oledOk) {
    oled.setTextSize(1);
    oled.setTextColor(SSD1306_WHITE);
    mostrarMensagemOLED("PROJETO C.A.S.A.", "Reset anterior:", motivoReset);
  }

  // 2. Combo SW1+SW2+SW3 por 2 s => modo configuracao
  bool forcarConfig = false;
  if (digitalRead(BTN_PINS[0]) == LOW && digitalRead(BTN_PINS[1]) == LOW && digitalRead(BTN_PINS[2]) == LOW) {
    mostrarMensagemOLED("MODO CONFIGURACAO?", "Mantenha pressionado", "por 2 segundos...");
    delay(2000);
    if (digitalRead(BTN_PINS[0]) == LOW && digitalRead(BTN_PINS[1]) == LOW && digitalRead(BTN_PINS[2]) == LOW) {
      forcarConfig = true;
    }
  }

  // NVS
  prefs.begin("casa_cfg", false);
  bootCount            = prefs.getUInt("boot_cnt", 0) + 1;
  prefs.putUInt("boot_cnt", bootCount);
  ownerUid             = prefs.getString("owner_uid", "");
  reparPendente        = prefs.getBool("repar", false);
  reparBase            = prefs.getString("rep_base", "-");
  pinPendente          = prefs.getString("pin_pend", "");
  refreshToken         = prefs.getString("fb_refresh", "");
  configVersaoLocal    = prefs.getInt("cfg_ver", -1);
  alertaBateriaEnviado = prefs.getBool("bat_alert", false);
  prefs.end();
  carregarRedesNVS();

  if (strlen(FIREBASE_API_KEY) == 0) {
    Serial.println("[AVISO] FIREBASE_API_KEY vazio: sem login anonimo (so funciona com regras abertas).");
  }

  // 3. TFTs
  for (int i = 0; i < 8; i++) {
    pinMode(TFT_CS_PINS[i], OUTPUT);
    digitalWrite(TFT_CS_PINS[i], HIGH);
  }
  spiTFT.begin(TFT_SCL, -1, TFT_SDA, -1);
  for (int i = 0; i < 8; i++) {
    tft[i].init(240, 240);
    tft[i].invertDisplay(true);
    spiTFT.begin(TFT_SCL, -1, TFT_SDA, -1);
    tft[i].setRotation(i < 3 ? TFT_ROTACAO_CATEGORIAS : TFT_ROTACAO_ACOES);
    tft[i].fillScreen(ST77XX_BLACK);
  }
  TJpgDec.setJpgScale(1);
  TJpgDec.setSwapBytes(false);
  TJpgDec.setCallback(tft_output);

  // 4. SD
  pinMode(SD_CS, OUTPUT);
  digitalWrite(SD_CS, HIGH);
  pinMode(SD_MISO, INPUT_PULLUP);
  spiSD.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  sdDisponivel = montarSD();
  carregarMetadadosPranchaDoSD();
  carregarManifesto();

  // 5. Audio
  audio.setPinout(I2S_BCLK, I2S_LRC, I2S_DIN);
  audio.forceMono(true);
  audio.setVolume(min(VOLUME_PADRAO, VOLUME_MAXIMO));

  // 6. Modo
  bool temConteudoNoSD = sdDisponivel && (sdExiste("/cat1") || sdExiste("/cat2") || sdExiste("/cat3"));
  modoAtual = (forcarConfig || (!temRedesConfiguradas && !temConteudoNoSD)) ? MODO_CONFIG : MODO_UTILIZACAO;
  configPodeExpirar = (modoAtual == MODO_CONFIG) && (temRedesConfiguradas || temConteudoNoSD);
  inicioConfigMs = millis();
  Serial.printf("[MODO] %s | combo=%d | redes=%d | SD=%d | repar=%d\n",
                modoAtual == MODO_CONFIG ? "CONFIG (BLE)" : "UTILIZACAO",
                forcarConfig, numRedes, sdDisponivel, reparPendente);

  if (modoAtual == MODO_CONFIG) {
    String nomeBle = "CASA-" + macSemPontos.substring(8, 12);
    nomeBleAtual = nomeBle;
    iniciarVibracao(250);

    BLEDevice::init(nomeBle.c_str());
    gerarPinBle();
    mostrarTelaConfigBle();
    BLEDevice::setMTU(517);
    BLEServer* pServer = BLEDevice::createServer();
    pServer->setCallbacks(new BLEServerCallbacksCustom());
    BLEService* pService = pServer->createService(SERVICE_UUID);

    BLECharacteristic* pCfg = pService->createCharacteristic(CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_WRITE);
    pCfg->setCallbacks(new BLEConfigCallbacks());

    BLECharacteristic* pMac = pService->createCharacteristic(MAC_CHAR_UUID, BLECharacteristic::PROPERTY_READ);
    pMac->setValue(macComPontos.c_str());

    pBleStatus = pService->createCharacteristic(STATUS_CHAR_UUID, BLECharacteristic::PROPERTY_READ);
    pBleStatus->setValue("aguardando_pin");

    pService->start();
    BLEAdvertising* pAdv = BLEDevice::getAdvertising();
    pAdv->addServiceUUID(SERVICE_UUID);
    pAdv->setScanResponse(true);
    BLEDevice::startAdvertising();
    Serial.printf("[BLE] Anunciando como '%s' (PIN no OLED)\n", nomeBle.c_str());
  } else {
    iniciarVibracao(80);
    carregarPranchaCategoria(1, 0);
    logResumoSD("boot");
    xTaskCreatePinnedToCore(taskSincronizacaoNuvem, "SyncTask", 32768, NULL, 1, NULL, 0);
#if LOG_SERVER_ATIVO
    xTaskCreatePinnedToCore(taskLogServer, "LogSrv", 8192, NULL, 1, NULL, 0);
#endif

    // Le o estado fisico real dos pinos apos estabilizar os perifericos (evita falso clique no boot)
    delay(50);
    bootFimSetupMs = millis();
    for (uint8_t i = 0; i < 8; i++) {
      estadoAnteriorBtn[i] = digitalRead(BTN_PINS[i]);
      ultimoCliqueBtn[i] = bootFimSetupMs;
      if (estadoAnteriorBtn[i] == LOW) {
        Serial.printf("[BTN] Aviso: GPIO %d iniciou em LOW no boot (ignorado)\n", BTN_PINS[i]);
      }
    }
  }
}

// =====================================================================
// LOOP (Core 1)
// =====================================================================
void loop() {
  if (modoAtual == MODO_CONFIG) {
    if (blePinRenovar) {
      blePinRenovar = false;
      gerarPinBle();
      mostrarTelaConfigBle();
    }
    if (bleRecebeuConfig) {
      mostrarMensagemOLED("DADOS SALVOS!", "Reiniciando...");
      iniciarVibracao(300);
      delay(1500);
      ESP.restart();
    }
    if (configPodeExpirar && (millis() - inicioConfigMs >= CONFIG_BLE_TIMEOUT_MS)) {
      mostrarMensagemOLED("CONFIG EXPIROU", "Voltando ao uso...");
      delay(1500);
      ESP.restart();
    }
    delay(20);
    return;
  }

  if (!sdDisponivel && millis() - ultimaTentativaSD >= SD_RETRY_MS) {
    ultimaTentativaSD = millis();
    if (montarSD()) {
      sdDisponivel = true;
      carregarMetadadosPranchaDoSD();
      carregarManifesto();
      carregarPranchaCategoria(categoriaAtiva, 0);
      logResumoSD("SD reconectado");
    }
  }

  if (recarregarTelasPendente && !audio.isRunning()) {
    recarregarTelasPendente = false;
    iniciarVibracao(120);
    carregarPranchaCategoria(categoriaAtiva, 0);
    logResumoSD("apos sincronizar");
    if (!categoriaExiste[categoriaAtiva - 1]) {
      for (int i = 0; i < 3; i++) {
        if (categoriaExiste[i]) { carregarPranchaCategoria(i + 1, 0); break; }
      }
    }
  }

  if (volumePendente >= 0) {
    audio.setVolume((uint8_t)volumePendente);
    volumePendente = -1;
  }

  if (sdDisponivel && xSemaphoreTake(sdMutex, pdMS_TO_TICKS(5)) == pdTRUE) {
    audio.loop();
    xSemaphoreGive(sdMutex);
  }

  processarLogsPendentesNoSD();

#if LOG_SERVER_ATIVO
  static unsigned long ultimoHeartbeat = 0;
  if (millis() - ultimoHeartbeat >= 30000) {
    ultimoHeartbeat = millis();
    float bat = obterBateriaThreadSafe();
    Serial.printf("[HEARTBEAT] Cat %d | Bat %.0f%% | Heap %u | SD %s | Wi-Fi %s | Sync %d\n",
                  categoriaAtiva, bat, (unsigned)ESP.getFreeHeap(), sdDisponivel ? "ok" : "ERRO",
                  WiFi.status() == WL_CONNECTED ? "ok" : "off", (int)statusSync);
  }
#endif

  unsigned long agora = millis();
  if (agora - bootFimSetupMs < BOOT_GUARD_MS) {
    for (uint8_t i = 0; i < 8; i++) estadoAnteriorBtn[i] = digitalRead(BTN_PINS[i]);
    return;
  }

  for (uint8_t i = 0; i < 8; i++) {
    bool leituraAtual = digitalRead(BTN_PINS[i]);

    if (estadoAnteriorBtn[i] == HIGH && leituraAtual == LOW) {
      if (agora - ultimoCliqueBtn[i] >= DEBOUNCE_MS) {
        ultimoCliqueBtn[i] = agora;

        if (i < 3) {
          uint8_t novaCat = i + 1;
          if (novaCat != categoriaAtiva && categoriaExiste[i]) {
            if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
              audio.stopSong();
              xSemaphoreGive(sdMutex);
            }
            iniciarVibracao(50);
            carregarPranchaCategoria(novaCat, categoriaAtiva);
          }
          if (categoriaExiste[i]) tocarAudioCategoria(novaCat);
        } else {
          dispararBotaoComunicacao(i - 3);
        }
      }
    }
    estadoAnteriorBtn[i] = leituraAtual;
  }
}

void audio_info(const char *info) { Serial.printf("[AUDIO] %s\n", info); }
void audio_eof_mp3(const char *info) { Serial.printf("[AUDIO FIM] %s\n", info); }