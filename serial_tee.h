// serial_tee.h  -  copies everything the sketch prints to the Serial Monitor
// onto the Command Center page (encrypted with AES-256-GCM, same key as the
// sketch already uses). Serial Monitor keeps working exactly as before.
//
// HOW TO USE (two small edits in the main sketch):
//   1. Put this file in the sketch folder and add, AFTER the other #include
//      lines at the top:
//          #include "serial_tee.h"
//   2. In setup(), right after Serial.begin(115200); add ONE line
//      (the exact line is given in the instructions for each device).
//
// Nothing else changes: the sketch's own Serial.print / println / printf
// calls are captured automatically.

#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <mbedtls/gcm.h>
#include <mbedtls/base64.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>

#define TEE_MAX_LINES 40
#define TEE_LINE_LEN 150
#define TEE_BATCH 14

static char tee_lines[TEE_MAX_LINES][TEE_LINE_LEN];
static volatile int tee_head = 0;   // next line to send
static volatile int tee_tail = 0;   // next free slot
static char tee_cur[TEE_LINE_LEN];
static int tee_len = 0;
static SemaphoreHandle_t tee_mutex = nullptr;

static void tee_push_line() {
  if (tee_len == 0) return;
  tee_cur[tee_len] = 0;
  if (tee_mutex) xSemaphoreTake(tee_mutex, portMAX_DELAY);
  int next = (tee_tail + 1) % TEE_MAX_LINES;
  if (next == tee_head) tee_head = (tee_head + 1) % TEE_MAX_LINES;  // drop oldest
  memcpy(tee_lines[tee_tail], tee_cur, tee_len + 1);
  tee_tail = next;
  if (tee_mutex) xSemaphoreGive(tee_mutex);
  tee_len = 0;
}

class TeeSerial : public Stream {
 public:
  void begin(unsigned long baud) { Serial.begin(baud); }
  void begin(unsigned long baud, uint32_t cfg, int8_t rx = -1, int8_t tx = -1) {
    Serial.begin(baud, cfg, rx, tx);
  }
  void end() { Serial.end(); }
  size_t write(uint8_t c) override {
    Serial.write(c);
    if (c == '\n') {
      tee_push_line();
    } else if (c >= 32 && c < 127 && tee_len < TEE_LINE_LEN - 1) {
      tee_cur[tee_len++] = (char)c;
    }
    return 1;
  }
  int available() override { return Serial.available(); }
  int read() override { return Serial.read(); }
  int peek() override { return Serial.peek(); }
  using Print::write;
  void flush() override { Serial.flush(); }
  operator bool() { return true; }
};

static TeeSerial tee_serial;
#define Serial tee_serial

// ---------------------------------------------------------------
// sender
// ---------------------------------------------------------------
static const char* tee_url = nullptr;
static const char* tee_device = nullptr;
static const char* tee_aad = nullptr;
static uint8_t tee_key[32];
static unsigned long tee_last_ok = 0;

static int tee_hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool tee_key_from_hex(const char* hex) {
  if (!hex || strlen(hex) != 64) return false;
  for (int i = 0; i < 32; i++) {
    int a = tee_hexval(hex[2 * i]), b = tee_hexval(hex[2 * i + 1]);
    if (a < 0 || b < 0) return false;
    tee_key[i] = (uint8_t)((a << 4) | b);
  }
  return true;
}

static String tee_b64(const uint8_t* d, size_t n) {
  size_t outLen = 0;
  size_t cap = ((n + 2) / 3) * 4 + 4;
  unsigned char* buf = (unsigned char*)malloc(cap);
  if (!buf) return String();
  mbedtls_base64_encode(buf, cap, &outLen, d, n);
  buf[outLen] = 0;
  String s((char*)buf);
  free(buf);
  return s;
}

static bool tee_send_batch(const String& plain) {
  size_t n = plain.length();
  uint8_t* ct = (uint8_t*)malloc(n);
  if (!ct) return false;
  uint8_t nonce[12], tag[16];
  esp_fill_random(nonce, 12);

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, tee_key, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(
        &gcm, MBEDTLS_GCM_ENCRYPT, n, nonce, 12,
        (const unsigned char*)tee_aad, strlen(tee_aad),
        (const unsigned char*)plain.c_str(), ct, 16, tag);
  }
  mbedtls_gcm_free(&gcm);
  if (rc != 0) { free(ct); return false; }

  String body = "{\"device_id\":\"";
  body += tee_device;
  body += "\",\"nonce\":\"" + tee_b64(nonce, 12);
  body += "\",\"ciphertext\":\"" + tee_b64(ct, n);
  body += "\",\"tag\":\"" + tee_b64(tag, 16) + "\"}";
  free(ct);

  HTTPClient http;
  http.setConnectTimeout(1500);
  http.setTimeout(2000);
  if (!http.begin(tee_url)) return false;
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(body);
  http.end();
  return code == 200;
}

static void tee_task(void*) {
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(800));
    if (WiFi.status() != WL_CONNECTED) continue;

    // Nothing printed for a while: still send a tiny "I am alive" packet,
    // so the Command Center knows this device is plugged in and online.
    if (tee_head == tee_tail) {
      if (millis() - tee_last_ok > 3000) {
        if (tee_send_batch(String("{\"kind\":\"serial\",\"lines\":[]}"))) tee_last_ok = millis();
      }
      continue;
    }

    String plain = "{\"kind\":\"serial\",\"lines\":[";
    int taken = 0;
    int h = tee_head;
    if (tee_mutex) xSemaphoreTake(tee_mutex, portMAX_DELAY);
    while (h != tee_tail && taken < TEE_BATCH) {
      if (taken) plain += ",";
      plain += "\"";
      for (const char* p = tee_lines[h]; *p; p++) {
        if (*p == '"' || *p == '\\') plain += '\\';
        plain += *p;
      }
      plain += "\"";
      h = (h + 1) % TEE_MAX_LINES;
      taken++;
    }
    if (tee_mutex) xSemaphoreGive(tee_mutex);
    plain += "]}";

    if (tee_send_batch(plain)) {
      if (tee_mutex) xSemaphoreTake(tee_mutex, portMAX_DELAY);
      tee_last_ok = millis();
      tee_head = h;   // only forget the lines once the server accepted them
      if (tee_mutex) xSemaphoreGive(tee_mutex);
    }
  }
}

// Call once in setup(), right after Serial.begin(...).
//   url    : full address of /api/device-log on the laptop
//   device : "ESP32_01" or "ESP32-CAM"
//   aad    : device id for ESP32_01, "ESP32-CAM:LOG" for the camera
//   keyHex : the 64-character AES key text the sketch already holds
static void startLogSyncHex(const char* url, const char* device,
                            const char* aad, const char* keyHex) {
  if (!tee_key_from_hex(keyHex)) return;
  tee_url = url; tee_device = device; tee_aad = aad;
  if (!tee_mutex) tee_mutex = xSemaphoreCreateMutex();
  xTaskCreate(tee_task, "tee_log", 8192, nullptr, 1, nullptr);
}

// Same, for a sketch that keeps its key as 32 raw bytes.
static void startLogSyncBytes(const char* url, const char* device,
                              const char* aad, const unsigned char* key32) {
  memcpy(tee_key, key32, 32);
  tee_url = url; tee_device = device; tee_aad = aad;
  if (!tee_mutex) tee_mutex = xSemaphoreCreateMutex();
  xTaskCreate(tee_task, "tee_log", 8192, nullptr, 1, nullptr);
}
