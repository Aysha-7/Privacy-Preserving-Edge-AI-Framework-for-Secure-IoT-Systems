/*
  Secure IoT DHT11 + TinyML node - non-blocking encrypted uploader

  What changed compared with DHT11_TinyML_Debug.ino:
    * The sensor/TinyML loop never waits for the network. Uploads run in a
      separate FreeRTOS task.
    * TCP connect time and HTTP response time are measured and logged
      separately. A fast failure (refused) and a slow failure (timeout,
      packets dropped) are reported differently.
    * HIGH_HUMIDITY events go into a bounded queue and are retried with
      exponential backoff until the server accepts them. If the queue is
      full the OLDEST anomaly is dropped with a loud warning.
    * NORMAL readings use a single "latest value" slot. They are never
      queued, never retried, and never pile up.
    * Success is printed only when the server really returned HTTP 200/201.

  Unchanged on purpose: TinyML model and preprocessing, the 70% rule,
  AES-256-GCM, 12-byte nonce, 16-byte tag, Base64, JSON envelope and
  device_id as associated data, device ID and endpoint.
*/

#include <Arduino.h>
#include <DHT.h>
#include <Chirale_TensorFlowLite.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <HTTPClient.h>
#include <math.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>

#include <mbedtls/gcm.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <esp_system.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "model_data.h"

#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/micro/micro_mutable_op_resolver.h"
#include "tensorflow/lite/schema/schema_generated.h"

// =====================================================
// DHT11 SENSOR
// =====================================================

#define DHTPIN 4
#define DHTTYPE DHT11

DHT dht(DHTPIN, DHTTYPE);

// =====================================================
// WI-FI AND FLASK SERVER
// =====================================================

const char* WIFI_SSID = "FTTH";

// Keep your actual Wi-Fi password here. Do not share it.
const char* WIFI_PASSWORD = "12345678";

// Windows laptop Wi-Fi IPv4 address (check with ipconfig).
// Full endpoint: http://SERVER_HOST:SERVER_PORT/api/sensor
const char* SERVER_HOST = "192.168.1.36";
const uint16_t SERVER_PORT = 5000;
const char* SERVER_PATH = "/api/sensor";
const char* DEVICE_ID = "ESP32_01";

// =====================================================
// DETECTION RULE
// =====================================================

// Strictly greater than 70% means HIGH_HUMIDITY.
// Exactly 70% is NORMAL. Change > to >= in loop() if needed.
constexpr float HUMIDITY_THRESHOLD = 70.0f;

// =====================================================
// TIMING AND RETRY SETTINGS (all easy to tune)
// =====================================================

constexpr unsigned long SAMPLE_INTERVAL_MS = 2000UL;

// true  = also send NORMAL readings as a heartbeat (server stores them
//         locally only; no Cloudinary/Fabric for NORMAL).
// false = anomaly-only: NORMAL readings never leave the device.
constexpr bool SEND_NORMAL_READINGS = true;
constexpr unsigned long NORMAL_UPLOAD_INTERVAL_MS = 5000UL;

// First HIGH reading is sent immediately. While humidity stays HIGH, a new
// anomaly event is queued at most this often. Every HIGH event creates a
// Cloudinary upload and a Fabric block, so keep this reasonably large.
constexpr unsigned long HIGH_REPEAT_INTERVAL_MS = 30000UL;

// TCP connect timeout: on a local network a reachable server answers in a
// few milliseconds, so 2 seconds is generous.
constexpr int32_t TCP_CONNECT_TIMEOUT_MS = 2000;
constexpr uint16_t HTTP_RESPONSE_TIMEOUT_MS = 30000;

constexpr unsigned long RETRY_BACKOFF_MIN_MS = 2000UL;
constexpr unsigned long RETRY_BACKOFF_MAX_MS = 30000UL;

constexpr unsigned long WIFI_BOOT_TIMEOUT_MS = 10000UL;
constexpr unsigned long WIFI_RETRY_INTERVAL_MS = 10000UL;

// Maximum number of HIGH_HUMIDITY events waiting for upload.
constexpr int HIGH_QUEUE_LENGTH = 8;

// Fast failures (under this) look like an active refusal (TCP RST).
constexpr unsigned long FAST_FAILURE_MS = 500UL;

// =====================================================
// AES-256-GCM ENCRYPTION KEY
// =====================================================

// Paste your EXISTING 64-hex-character key here (the same value as
// AES_GCM_KEY_HEX in the Flask window). Never print this key.
// The sketch prints only a short fingerprint at startup so you can compare
// it with the Flask side without exposing the key.
const char* AES_KEY_HEX =
    "6b7d6492b907e9bac6ac2cf0e609781324e26afb049431b23d40fb249d40f820";

// =====================================================
// TINYML MODEL
// =====================================================

namespace {

constexpr int kTensorArenaSize = 12 * 1024;

alignas(16) uint8_t tensor_arena[kTensorArenaSize];

const tflite::Model* model = nullptr;
tflite::MicroInterpreter* interpreter = nullptr;

TfLiteTensor* input = nullptr;
TfLiteTensor* output = nullptr;

tflite::MicroMutableOpResolver<3> resolver;

}  // namespace

// =====================================================
// SHARED UPLOAD STATE
// =====================================================

struct Reading {
  float temperature;
  float humidity;
  bool high;
};

static QueueHandle_t highQueue = nullptr;    // bounded FIFO of anomalies
static QueueHandle_t normalSlot = nullptr;   // length 1, latest value only
static volatile uint32_t droppedAnomalies = 0;

enum class UploadResult {
  Success,
  TransportFailure,
  ServerRejected,
  InternalError
};

// =====================================================
// INPUT QUANTIZATION
// =====================================================

static int8_t quantizeInput(
    float value,
    float scale,
    int zero_point
) {
  int32_t q =
      static_cast<int32_t>(roundf(value / scale))
      + zero_point;

  if (q > 127) {
    q = 127;
  }

  if (q < -128) {
    q = -128;
  }

  return static_cast<int8_t>(q);
}

// =====================================================
// WI-FI
// =====================================================

// Used once in setup(). Blocks for at most WIFI_BOOT_TIMEOUT_MS.
static bool connectWiFiAtBoot() {
  Serial.print("Connecting to Wi-Fi: ");
  Serial.println(WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  const unsigned long start = millis();

  while (
      WiFi.status() != WL_CONNECTED &&
      millis() - start < WIFI_BOOT_TIMEOUT_MS
  ) {
    delay(250);
    Serial.print(".");
  }

  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("Wi-Fi connected!");

    Serial.print("ESP32 IP address: ");
    Serial.println(WiFi.localIP());

    Serial.print("Gateway: ");
    Serial.println(WiFi.gatewayIP());

    Serial.print("Signal strength (RSSI): ");
    Serial.print(WiFi.RSSI());
    Serial.println(" dBm");

    Serial.printf(
        "Flask endpoint: http://%s:%u%s\n",
        SERVER_HOST,
        (unsigned)SERVER_PORT,
        SERVER_PATH
    );

    return true;
  }

  Serial.println(
      "Wi-Fi not connected yet. The upload task will keep retrying."
  );

  return false;
}

// Used by the upload task. Never blocks.
static bool wifiReady() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  static unsigned long lastTry = 0;
  const unsigned long now = millis();

  if (lastTry == 0 || now - lastTry >= WIFI_RETRY_INTERVAL_MS) {
    lastTry = now;

    Serial.println("[WIFI] Not connected. Restarting connection...");

    WiFi.disconnect();
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  }

  return false;
}

// =====================================================
// KEY HANDLING
// =====================================================

bool hexKeyToBytes(
    const char* hex,
    uint8_t key[32]
) {
  if (hex == nullptr || strlen(hex) != 64) {
    return false;
  }

  for (int i = 0; i < 32; i++) {
    char pair[3] = {
        hex[i * 2],
        hex[i * 2 + 1],
        '\0'
    };

    char* end = nullptr;

    unsigned long value = strtoul(pair, &end, 16);

    if (
        end == pair ||
        *end != '\0' ||
        value > 255
    ) {
      return false;
    }

    key[i] = static_cast<uint8_t>(value);
  }

  return true;
}

// Short fingerprint of the key text: first 8 hex characters of
// SHA-256(key_hex_string). It matches this Windows/Python check:
//   python -c "import os,hashlib;v=os.environ['AES_GCM_KEY_HEX'].strip();
//              print(hashlib.sha256(v.encode()).hexdigest()[:8])"
// It cannot be used to recover the key. If this function causes a compile
// error on your ESP32 core version, delete it and its call in setup().
static void keyFingerprint(const char* hex, char out[9]) {
  uint8_t digest[32];

  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(
      &ctx,
      reinterpret_cast<const unsigned char*>(hex),
      strlen(hex)
  );
  mbedtls_sha256_finish(&ctx, digest);
#else
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(
      &ctx,
      reinterpret_cast<const unsigned char*>(hex),
      strlen(hex)
  );
  mbedtls_sha256_finish_ret(&ctx, digest);
#endif

  mbedtls_sha256_free(&ctx);

  snprintf(
      out,
      9,
      "%02x%02x%02x%02x",
      digest[0],
      digest[1],
      digest[2],
      digest[3]
  );
}

// =====================================================
// BASE64 ENCODING
// =====================================================

bool base64Encode(
    const uint8_t* inputData,
    size_t inputLength,
    String& result
) {
  const size_t outputLength =
      4 * ((inputLength + 2) / 3);

  unsigned char* encoded =
      static_cast<unsigned char*>(
          malloc(outputLength + 1)
      );

  if (encoded == nullptr) {
    return false;
  }

  size_t written = 0;

  const int rc = mbedtls_base64_encode(
      encoded,
      outputLength + 1,
      &written,
      inputData,
      inputLength
  );

  if (rc == 0) {
    encoded[written] = '\0';

    result = reinterpret_cast<char*>(encoded);
  }

  free(encoded);

  return rc == 0;
}

// =====================================================
// AES-256-GCM ENCRYPTION (unchanged)
// =====================================================

bool encryptPayload(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const char* deviceId,
    const uint8_t* plaintext,
    size_t plaintextLength,
    uint8_t* ciphertext,
    uint8_t tag[16]
) {
  mbedtls_gcm_context gcm;

  mbedtls_gcm_init(&gcm);

  int rc = mbedtls_gcm_setkey(
      &gcm,
      MBEDTLS_CIPHER_ID_AES,
      key,
      256
  );

  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(
        &gcm,
        MBEDTLS_GCM_ENCRYPT,
        plaintextLength,
        nonce,
        12,
        reinterpret_cast<const unsigned char*>(deviceId),
        strlen(deviceId),
        plaintext,
        ciphertext,
        16,
        tag
    );
  }

  mbedtls_gcm_free(&gcm);

  return rc == 0;
}

// =====================================================
// BUILD THE ENCRYPTED ENVELOPE
// Same JSON layout the Flask /api/sensor route expects:
//   {"device_id","nonce","ciphertext","tag"}  (Base64 values)
// A fresh nonce is generated for every call, including retries.
// =====================================================

static bool buildEnvelope(const Reading& reading, String& envelope) {
  uint8_t key[32];

  if (!hexKeyToBytes(AES_KEY_HEX, key)) {
    Serial.println(
        "ERROR: AES key must contain exactly 64 hex characters."
    );

    return false;
  }

  const char* prediction =
      reading.high ? "HIGH_HUMIDITY" : "NORMAL";

  String plaintext = "{";

  plaintext += "\"device_id\":\"";
  plaintext += DEVICE_ID;
  plaintext += "\",";

  plaintext += "\"temperature\":";
  plaintext += String(reading.temperature, 2);
  plaintext += ",";

  plaintext += "\"humidity\":";
  plaintext += String(reading.humidity, 2);
  plaintext += ",";

  plaintext += "\"prediction\":\"";
  plaintext += prediction;
  plaintext += "\"";

  plaintext += "}";

  const size_t plaintextLength = plaintext.length();

  uint8_t nonce[12];
  uint8_t tag[16];

  for (int i = 0; i < 3; i++) {
    const uint32_t randomValue = esp_random();

    memcpy(
        nonce + (i * sizeof(randomValue)),
        &randomValue,
        sizeof(randomValue)
    );
  }

  uint8_t* ciphertext =
      static_cast<uint8_t*>(
          malloc(plaintextLength)
      );

  if (ciphertext == nullptr) {
    memset(key, 0, sizeof(key));

    Serial.println(
        "ERROR: Could not allocate ciphertext buffer."
    );

    return false;
  }

  const bool encrypted = encryptPayload(
      key,
      nonce,
      DEVICE_ID,
      reinterpret_cast<const uint8_t*>(
          plaintext.c_str()
      ),
      plaintextLength,
      ciphertext,
      tag
  );

  // Clear the local key copy immediately.
  memset(key, 0, sizeof(key));

  if (!encrypted) {
    free(ciphertext);

    Serial.println(
        "ERROR: AES-256-GCM encryption failed."
    );

    return false;
  }

  String nonceB64;
  String ciphertextB64;
  String tagB64;

  const bool encoded =
      base64Encode(
          nonce,
          sizeof(nonce),
          nonceB64
      ) &&
      base64Encode(
          ciphertext,
          plaintextLength,
          ciphertextB64
      ) &&
      base64Encode(
          tag,
          sizeof(tag),
          tagB64
      );

  free(ciphertext);

  if (!encoded) {
    Serial.println("ERROR: Base64 encoding failed.");

    return false;
  }

  envelope = "{";

  envelope += "\"device_id\":\"";
  envelope += DEVICE_ID;
  envelope += "\",";

  envelope += "\"nonce\":\"";
  envelope += nonceB64;
  envelope += "\",";

  envelope += "\"ciphertext\":\"";
  envelope += ciphertextB64;
  envelope += "\",";

  envelope += "\"tag\":\"";
  envelope += tagB64;
  envelope += "\"";

  envelope += "}";

  return true;
}

// =====================================================
// HTTP: ONE UPLOAD ATTEMPT
// Step 1: plain TCP connect (timed separately)
// Step 2: HTTP POST over that connection (timed separately)
// =====================================================

static String jsonStringField(const String& body, const char* key) {
  const String needle = String("\"") + key + "\":\"";

  int start = body.indexOf(needle);

  if (start < 0) {
    return String("?");
  }

  start += needle.length();

  const int end = body.indexOf('"', start);

  if (end < 0) {
    return String("?");
  }

  return body.substring(start, end);
}

static UploadResult postEnvelope(
    const String& envelope,
    bool isHigh
) {
  WiFiClient client;

  // ---- Step 1: TCP connect -------------------------------------
  const unsigned long connectStart = millis();

  const int connected = client.connect(
      SERVER_HOST,
      SERVER_PORT,
      TCP_CONNECT_TIMEOUT_MS
  );

  const unsigned long connectMs = millis() - connectStart;

  if (!connected) {
    Serial.printf(
        "[UPLOAD] TCP connect to %s:%u FAILED after %lu ms\n",
        SERVER_HOST,
        (unsigned)SERVER_PORT,
        connectMs
    );

    if (connectMs < FAST_FAILURE_MS) {
      Serial.println(
          "[UPLOAD] Fast failure: the destination answered and refused. "
          "Check that Flask is running and the port is 5000."
      );
    } else {
      Serial.println(
          "[UPLOAD] Slow failure (timeout): packets are being dropped. "
          "Check the Windows Firewall rule and profile, the laptop "
          "IP, and Wi-Fi client isolation."
      );
    }

    return UploadResult::TransportFailure;
  }

  Serial.printf(
      "[UPLOAD] TCP connected in %lu ms\n",
      connectMs
  );

  // ---- Step 2: HTTP POST ---------------------------------------
  HTTPClient http;

  http.setReuse(false);
  http.setTimeout(HTTP_RESPONSE_TIMEOUT_MS);

  if (!http.begin(client, SERVER_HOST, SERVER_PORT, SERVER_PATH)) {
    Serial.println("[UPLOAD] ERROR: HTTP initialization failed.");

    client.stop();

    return UploadResult::InternalError;
  }

  http.addHeader("Content-Type", "application/json");

  const unsigned long requestStart = millis();

  const int httpCode = http.POST(envelope);

  const unsigned long responseMs = millis() - requestStart;

  if (httpCode <= 0) {
    Serial.printf(
        "[UPLOAD] HTTP transport error after %lu ms: %s\n",
        responseMs,
        http.errorToString(httpCode).c_str()
    );

    http.end();

    return UploadResult::TransportFailure;
  }

  const String body = http.getString();

  http.end();

  Serial.printf(
      "[UPLOAD] Server returned HTTP %d in %lu ms\n",
      httpCode,
      responseMs
  );

    if (httpCode == 200 || httpCode == 201) {
    if (isHigh) {
      Serial.printf(
          "[UPLOAD] Server reports: cloud=%s fabric=%s\n",
          jsonStringField(body, "cloud_storage_status").c_str(),
          jsonStringField(body, "fabric_status").c_str()
      );

      Serial.printf(
          "[UPLOAD] Fabric event ID: %s\n",
          jsonStringField(body, "fabric_event_id").c_str()
      );
    }

    return UploadResult::Success;
  }


  // Not a success. Show the beginning of the body so that API
  // rejections (for example 400 with an error message) are visible.
  Serial.print("[UPLOAD] Server rejected the request: ");
  Serial.println(body.substring(0, 160));

  return UploadResult::ServerRejected;
}

// =====================================================
// UPLOAD TASK
// Runs separately from loop(), so a slow or failing network can
// never delay sensor sampling or TinyML inference.
// =====================================================

static void uploadTask(void* parameter) {
  (void)parameter;

  Reading pending;
  bool havePending = false;

  unsigned long highBackoffMs = RETRY_BACKOFF_MIN_MS;
  unsigned long normalBackoffMs = RETRY_BACKOFF_MIN_MS;
  unsigned long normalPausedUntil = 0;
  uint32_t attempt = 0;

  for (;;) {
    // Pick the next item: anomalies first, then the latest NORMAL.
    // NORMAL readings are skipped while their own pause is active, so a
    // dead server is not hammered and anomalies are never delayed by it.
    if (!havePending) {
      if (xQueueReceive(highQueue, &pending, 0) == pdTRUE) {
        havePending = true;
      } else if (
          millis() >= normalPausedUntil &&
          xQueueReceive(normalSlot, &pending, 0) == pdTRUE
      ) {
        havePending = true;
      }

      if (!havePending) {
        vTaskDelay(pdMS_TO_TICKS(100));
        continue;
      }

      attempt = 0;
    }

    // Wi-Fi down: keep an anomaly (it is not lost) and wait.
    // A stale NORMAL reading is simply dropped.
    if (!wifiReady()) {
      if (!pending.high) {
        havePending = false;
      }

      vTaskDelay(pdMS_TO_TICKS(500));
      continue;
    }

    attempt++;

    Serial.printf(
        "[UPLOAD] Attempt %lu for %s reading\n",
        (unsigned long)attempt,
        pending.high ? "HIGH_HUMIDITY" : "NORMAL"
    );

    String envelope;
    UploadResult result = UploadResult::InternalError;

    if (buildEnvelope(pending, envelope)) {
      result = postEnvelope(envelope, pending.high);
    }

    if (result == UploadResult::Success) {
      Serial.println(
          "[UPLOAD] SUCCESS: the server accepted this reading."
      );

      if (pending.high) {
        highBackoffMs = RETRY_BACKOFF_MIN_MS;
      } else {
        normalBackoffMs = RETRY_BACKOFF_MIN_MS;
        normalPausedUntil = 0;
      }

      havePending = false;
      continue;
    }

    // ---- failure handling --------------------------------------
    if (!pending.high) {
      // NORMAL data is stale after a few seconds; the next heartbeat
      // replaces it. Do not retry it; just pause NORMAL uploads.
      Serial.printf(
          "[UPLOAD] NORMAL reading not delivered (not retried). "
          "NORMAL uploads paused for %lu ms.\n",
          normalBackoffMs
      );

      havePending = false;
      normalPausedUntil = millis() + normalBackoffMs;
      normalBackoffMs = min(normalBackoffMs * 2, RETRY_BACKOFF_MAX_MS);
      continue;
    }

    Serial.printf(
        "[UPLOAD] HIGH_HUMIDITY NOT delivered yet. Retrying in %lu ms "
        "(other anomalies waiting: %u)\n",
        highBackoffMs,
        (unsigned)uxQueueMessagesWaiting(highQueue)
    );

    vTaskDelay(pdMS_TO_TICKS(highBackoffMs));

    highBackoffMs = min(highBackoffMs * 2, RETRY_BACKOFF_MAX_MS);
  }
}

// =====================================================
// QUEUE HELPERS (called from loop)
// =====================================================

static void enqueueAnomaly(const Reading& reading) {
  if (xQueueSend(highQueue, &reading, 0) == pdTRUE) {
    Serial.printf(
        "[QUEUE] HIGH_HUMIDITY event queued (waiting: %u)\n",
        (unsigned)uxQueueMessagesWaiting(highQueue)
    );

    return;
  }

  // Queue full: make room by removing the OLDEST anomaly and say so.
  Reading oldest;

  xQueueReceive(highQueue, &oldest, 0);

  droppedAnomalies++;

  Serial.printf(
      "[QUEUE] WARNING: anomaly queue full. Dropped the OLDEST anomaly "
      "(total dropped: %lu). Fix the upload path.\n",
      (unsigned long)droppedAnomalies
  );

  xQueueSend(highQueue, &reading, 0);
}

static void offerNormalReading(const Reading& reading) {
  // Overwrites any older NORMAL value that has not been sent yet.
  xQueueOverwrite(normalSlot, &reading);
}

// =====================================================
// INITIALIZE TINYML (unchanged)
// =====================================================

bool initializeTinyML() {
  Serial.println("Initializing TinyML model...");

  model = tflite::GetModel(dht11_model);

  if (model == nullptr) {
    Serial.println("ERROR: Model pointer is null.");

    return false;
  }

  if (model->version() != TFLITE_SCHEMA_VERSION) {
    Serial.println(
        "ERROR: Model schema version mismatch."
    );

    return false;
  }

  if (
      resolver.AddFullyConnected() != kTfLiteOk ||
      resolver.AddRelu() != kTfLiteOk ||
      resolver.AddSoftmax() != kTfLiteOk
  ) {
    Serial.println(
        "ERROR: Could not register model operators."
    );

    return false;
  }

  static tflite::MicroInterpreter static_interpreter(
      model,
      resolver,
      tensor_arena,
      kTensorArenaSize
  );

  interpreter = &static_interpreter;

  if (interpreter->AllocateTensors() != kTfLiteOk) {
    Serial.println("ERROR: AllocateTensors failed.");

    return false;
  }

  input = interpreter->input(0);
  output = interpreter->output(0);

  if (input == nullptr || output == nullptr) {
    Serial.println(
        "ERROR: Input or output tensor is null."
    );

    return false;
  }

  if (
      input->type != kTfLiteInt8 ||
      output->type != kTfLiteInt8
  ) {
    Serial.println(
        "ERROR: Expected int8 input and output tensors."
    );

    return false;
  }

  if (input->bytes < 2 || output->bytes < 2) {
    Serial.println(
        "ERROR: Model tensors have unexpected dimensions."
    );

    return false;
  }

  if (
      input->params.scale <= 0.0f ||
      output->params.scale <= 0.0f
  ) {
    Serial.println(
        "ERROR: Invalid model quantization scale."
    );

    return false;
  }

  Serial.print("Input tensor scale: ");
  Serial.println(input->params.scale, 10);

  Serial.print("Input zero point: ");
  Serial.println(input->params.zero_point);

  Serial.print("Output tensor scale: ");
  Serial.println(output->params.scale, 10);

  Serial.print("Output zero point: ");
  Serial.println(output->params.zero_point);

  Serial.println("TinyML initialization successful.");

  return true;
}

// =====================================================
// SETUP
// =====================================================

void setup() {
  Serial.begin(115200);

  delay(500);

  Serial.println();
  Serial.println("====================================");
  Serial.println(" SECURE IOT DHT11 + TINYML (non-blocking)");
  Serial.println("====================================");

  dht.begin();

  connectWiFiAtBoot();

  if (!initializeTinyML()) {
    Serial.println(
        "FATAL: TinyML initialization failed. Check model_data.h."
    );

    while (true) {
      delay(1000);
    }
  }

  // Key sanity check and fingerprint (the key itself is never printed).
  uint8_t testKey[32];

  if (hexKeyToBytes(AES_KEY_HEX, testKey)) {
    char fingerprint[9];

    keyFingerprint(AES_KEY_HEX, fingerprint);

    Serial.print("AES key fingerprint: ");
    Serial.println(fingerprint);
  } else {
    Serial.println(
        "ERROR: AES_KEY_HEX is not a valid 64-character hex key. "
        "Uploads will fail until it is fixed."
    );
  }

  memset(testKey, 0, sizeof(testKey));

  // Queues must exist before the upload task starts.
  highQueue = xQueueCreate(HIGH_QUEUE_LENGTH, sizeof(Reading));
  normalSlot = xQueueCreate(1, sizeof(Reading));

  if (highQueue == nullptr || normalSlot == nullptr) {
    Serial.println("FATAL: Could not create upload queues.");

    while (true) {
      delay(1000);
    }
  }

  const BaseType_t created = xTaskCreatePinnedToCore(
      uploadTask,
      "upload",
      16384,
      nullptr,
      1,
      nullptr,
      0
  );

  if (created != pdPASS) {
    Serial.println("FATAL: Could not start upload task.");

    while (true) {
      delay(1000);
    }
  }
  //startPulseTask();
  Serial.println();
  Serial.println("Device ready.");
  Serial.println("Humidity threshold: > 70% = HIGH_HUMIDITY");
  Serial.println("Sampling interval: 2 seconds");

  Serial.print("Send NORMAL heartbeat: ");
  Serial.println(SEND_NORMAL_READINGS ? "yes" : "no (anomaly-only)");

  Serial.print("Device ID: ");
  Serial.println(DEVICE_ID);
}

// =====================================================
// MAIN LOOP: sensing and TinyML only. No network waiting.
// =====================================================

void loop() {
  static unsigned long lastSample = 0;
  static unsigned long lastHighQueued = 0;
  static unsigned long lastNormalQueued = 0;
  static bool wasHigh = false;
  static bool normalSentOnce = false;

  const unsigned long now = millis();

  if (now - lastSample < SAMPLE_INTERVAL_MS) {
    delay(10);
    return;
  }

  lastSample = now;

  const unsigned long workStart = millis();

  // -----------------------------------------------
  // READ DHT11
  // -----------------------------------------------

  const float temperature = dht.readTemperature();
  const float humidity = dht.readHumidity();

  if (
      isnan(temperature) ||
      isnan(humidity) ||
      !isfinite(temperature) ||
      !isfinite(humidity)
  ) {
    Serial.println(
        "ERROR: DHT11 reading failed. Check wiring and pin 4."
    );

    return;
  }

  // -----------------------------------------------
  // PREPROCESS FOR TINYML (unchanged)
  // -----------------------------------------------

  const float temperature_feature =
      (temperature - 20.0f) / 20.0f;

  const float humidity_feature =
      humidity / 100.0f;

  const float input_scale =
      input->params.scale;

  const int input_zero_point =
      input->params.zero_point;

  if (input_scale <= 0.0f) {
    Serial.println(
        "ERROR: Invalid input quantization scale."
    );

    return;
  }

  const int8_t q_temperature = quantizeInput(
      temperature_feature,
      input_scale,
      input_zero_point
  );

  const int8_t q_humidity = quantizeInput(
      humidity_feature,
      input_scale,
      input_zero_point
  );

  Serial.println();
  Serial.printf("------ SAMPLE at t=%lu ms ------\n", now);

  Serial.print("Temperature: ");
  Serial.print(temperature, 2);
  Serial.println(" C");

  Serial.print("Humidity: ");
  Serial.print(humidity, 2);
  Serial.println(" %");

  Serial.print("Quantized inputs: ");
  Serial.print((int)q_temperature);
  Serial.print(", ");
  Serial.println((int)q_humidity);

  // -----------------------------------------------
  // RUN TINYML MODEL (unchanged)
  // -----------------------------------------------

  input->data.int8[0] = q_temperature;
  input->data.int8[1] = q_humidity;

  if (interpreter->Invoke() != kTfLiteOk) {
    Serial.println(
        "ERROR: TinyML model invocation failed."
    );

    return;
  }

  const int raw0 = output->data.int8[0];
  const int raw1 = output->data.int8[1];

  const float score0 =
      (raw0 - output->params.zero_point) *
      output->params.scale;

  const float score1 =
      (raw1 - output->params.zero_point) *
      output->params.scale;

  const int modelPredicted =
      (raw1 > raw0) ? 1 : 0;

  const char* modelLabel =
      modelPredicted == 1
          ? "HIGH_HUMIDITY"
          : "NORMAL";

  Serial.print("TinyML prediction: ");
  Serial.println(modelLabel);

  Serial.print("TinyML scores: NORMAL=");
  Serial.print(score0, 4);

  Serial.print(", HIGH_HUMIDITY=");
  Serial.println(score1, 4);

  // -----------------------------------------------
  // EXPLICIT 70% RULE (takes priority for the final label)
  // -----------------------------------------------

  const bool isHigh = (humidity > HUMIDITY_THRESHOLD);

  const char* finalLabel =
      isHigh ? "HIGH_HUMIDITY" : "NORMAL";

  Serial.print("Final prediction: ");
  Serial.println(finalLabel);

  // -----------------------------------------------
  // HAND OFF TO THE UPLOAD TASK (never blocks)
  // -----------------------------------------------

  const Reading reading = {temperature, humidity, isHigh};

  if (isHigh) {
    Serial.println("!!! HIGH HUMIDITY ANOMALY DETECTED !!!");

    const bool risingEdge = !wasHigh;

    if (
        risingEdge ||
        now - lastHighQueued >= HIGH_REPEAT_INTERVAL_MS
    ) {
      enqueueAnomaly(reading);

      lastHighQueued = now;
    }
  } else {
    Serial.println("Humidity is within the normal range.");

    if (
        SEND_NORMAL_READINGS &&
        (!normalSentOnce ||
         now - lastNormalQueued >= NORMAL_UPLOAD_INTERVAL_MS)
    ) {
      offerNormalReading(reading);

      normalSentOnce = true;
      lastNormalQueued = now;
    }
  }

  wasHigh = isHigh;

  Serial.print("CSV diagnostic: ");

  Serial.print(temperature, 2);
  Serial.print(",");

  Serial.print(humidity, 2);
  Serial.print(",");

  Serial.print(finalLabel);
  Serial.print(",");

  Serial.print(score0, 4);
  Serial.print(",");

  Serial.println(score1, 4);

  // If a failing upload were blocking this loop, this number would
  // jump to several thousand milliseconds. It should stay small.
  Serial.printf(
      "Sample processing time: %lu ms\n",
      millis() - workStart
  );
}
