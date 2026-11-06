#include <Arduino.h>
#include <DHT.h>
#include <Chirale_TensorFlowLite.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <HTTPClient.h>
#include <math.h>

#include <mbedtls/gcm.h>
#include <mbedtls/base64.h>
#include <esp_system.h>
#include <stdint.h>
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

const char* WIFI_SSID = "ICSB";

// Keep your actual Wi-Fi password here.
// Do not share it publicly.
const char* WIFI_PASSWORD = "PASSWORD";

// IMPORTANT:
// Replace this IP if your Windows computer's IPv4
// address has changed. The ESP32 must be able to
// reach this address over the local network.
const char* SERVER_URL =
    "http://172.21.1.248:5000/api/sensor";

const char* DEVICE_ID = "ESP32_01";

// =====================================================
// HUMIDITY THRESHOLD
// =====================================================

// Strictly greater than 70% means HIGH_HUMIDITY.
// Exactly 70% is NORMAL.
// Change > to >= if 70% itself should be HIGH_HUMIDITY.
constexpr float HUMIDITY_THRESHOLD = 70.0f;

// =====================================================
// UPLOAD TIMING
// =====================================================

// Upload a reading every 5 seconds for the demonstration.
// DHT11 readings are still sampled every 2 seconds.
constexpr unsigned long SAMPLE_INTERVAL_MS = 2000UL;
constexpr unsigned long UPLOAD_INTERVAL_MS = 5000UL;

// Short timeout values help avoid long blocking requests.
constexpr unsigned long WIFI_CONNECT_TIMEOUT_MS = 10000UL;
constexpr uint16_t HTTP_CONNECT_TIMEOUT_MS = 3000;
constexpr uint16_t HTTP_RESPONSE_TIMEOUT_MS = 4000;

// =====================================================
// AES-256-GCM ENCRYPTION KEY
// =====================================================

// Preserve the existing key.
// It must exactly match AES_GCM_KEY_HEX in server.py.
// Never print this key to Serial Monitor.

const char* AES_KEY_HEX =
    "1a217e1d8bfac99526b951d94defdeb188b7f229a9d25b0bd4bbd2a8e50d6f32";

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

}

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
// WI-FI CONNECTION
// =====================================================

bool connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  Serial.print("Connecting to Wi-Fi: ");
  Serial.println(WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  const unsigned long startAttempt = millis();

  while (
      WiFi.status() != WL_CONNECTED &&
      millis() - startAttempt < WIFI_CONNECT_TIMEOUT_MS
  ) {
    delay(250);
    Serial.print(".");
  }

  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("Wi-Fi connected!");

    Serial.print("ESP32 IP address: ");
    Serial.println(WiFi.localIP());

    Serial.print("Signal strength (RSSI): ");
    Serial.print(WiFi.RSSI());
    Serial.println(" dBm");

    Serial.print("Flask server URL: ");
    Serial.println(SERVER_URL);

    return true;
  }

  Serial.println(
      "Wi-Fi connection failed. Will retry automatically."
  );

  return false;
}

// =====================================================
// CONVERT 64-CHAR HEX KEY TO 32 BYTES
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
// AES-256-GCM ENCRYPTION
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
// SEND ENCRYPTED SENSOR READING TO FLASK
// =====================================================

bool sendToServer(
    float temperature,
    float humidity,
    const char* prediction
) {
  Serial.println();
  Serial.println("Preparing encrypted sensor reading...");

  // -----------------------------------------------
  // CHECK WI-FI
  // -----------------------------------------------

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Wi-Fi disconnected. Reconnecting...");

    if (!connectWiFi()) {
      Serial.println(
          "Upload failed: Wi-Fi is unavailable."
      );

      return false;
    }
  }

  // -----------------------------------------------
  // DECODE AES KEY
  // -----------------------------------------------

  uint8_t key[32];

  if (!hexKeyToBytes(AES_KEY_HEX, key)) {
    Serial.println(
        "ERROR: AES key must contain 64 valid hex characters."
    );

    return false;
  }

  // -----------------------------------------------
  // CREATE PLAINTEXT JSON IN MEMORY
  // -----------------------------------------------

  String plaintext = "{";

  plaintext += "\"device_id\":\"";
  plaintext += DEVICE_ID;
  plaintext += "\",";

  plaintext += "\"temperature\":";
  plaintext += String(temperature, 2);
  plaintext += ",";

  plaintext += "\"humidity\":";
  plaintext += String(humidity, 2);
  plaintext += ",";

  plaintext += "\"prediction\":\"";
  plaintext += prediction;
  plaintext += "\"";

  plaintext += "}";

  const size_t plaintextLength = plaintext.length();

  // -----------------------------------------------
  // GENERATE A FRESH 12-BYTE NONCE
  // -----------------------------------------------

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

  // -----------------------------------------------
  // ALLOCATE CIPHERTEXT BUFFER
  // -----------------------------------------------

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

  // -----------------------------------------------
  // ENCRYPT AND AUTHENTICATE
  // -----------------------------------------------

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

  // Clear the local key buffer.
  memset(key, 0, sizeof(key));

  if (!encrypted) {
    free(ciphertext);

    Serial.println(
        "ERROR: AES-256-GCM encryption failed."
    );

    return false;
  }

  // -----------------------------------------------
  // BASE64-ENCODE NONCE, CIPHERTEXT AND TAG
  // -----------------------------------------------

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
    Serial.println(
        "ERROR: Base64 encoding failed."
    );

    return false;
  }

  // -----------------------------------------------
  // CREATE ENCRYPTED ENVELOPE
  // -----------------------------------------------

  String envelope = "{";

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

  Serial.println("AES-256-GCM encryption completed.");
  Serial.println("Sending encrypted JSON to Flask...");

  // -----------------------------------------------
  // SEND HTTP POST
  // -----------------------------------------------

  WiFiClient client;
  HTTPClient http;

  http.setConnectTimeout(HTTP_CONNECT_TIMEOUT_MS);
  http.setTimeout(HTTP_RESPONSE_TIMEOUT_MS);

  if (!http.begin(client, SERVER_URL)) {
    Serial.println(
        "ERROR: HTTP initialization failed."
    );

    return false;
  }

  http.addHeader(
      "Content-Type",
      "application/json"
  );

  const unsigned long requestStart = millis();

  const int httpCode = http.POST(envelope);

  const unsigned long requestDuration =
      millis() - requestStart;

  bool success = false;

  if (httpCode > 0) {
    Serial.print("HTTP response code: ");
    Serial.println(httpCode);

    Serial.print("HTTP request duration: ");
    Serial.print(requestDuration);
    Serial.println(" ms");

    // The response contains server status, not the
    // original plaintext sensor payload.
    const String response = http.getString();

    Serial.print("Server response: ");
    Serial.println(response);

    // The Flask endpoint may return 200 or 201
    // depending on its current implementation.
    if (httpCode == 200 || httpCode == 201) {
      Serial.println(
          "SUCCESS: Sensor reading accepted by Flask."
      );

      success = true;
    } else {
      Serial.println(
          "ERROR: Flask returned a non-success status."
      );
    }
  } else {
    Serial.print("HTTP request failed: ");
    Serial.println(http.errorToString(httpCode));

    Serial.print("Request duration: ");
    Serial.print(requestDuration);
    Serial.println(" ms");

    Serial.println(
        "Check SERVER_URL, Windows firewall, and Flask status."
    );
  }

  http.end();

  return success;
}

// =====================================================
// INITIALIZE TINYML
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
    Serial.println(
        "ERROR: AllocateTensors failed."
    );

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

  // This firmware expects exactly two model inputs:
  // temperature feature and humidity feature.
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
  Serial.println(" SECURE IOT DHT11 + TINYML");
  Serial.println("====================================");

  // Start the sensor.
  dht.begin();

  // Start Wi-Fi, but don't permanently halt the device
  // if the network is temporarily unavailable.
  connectWiFi();

  // Initialize the model.
  if (!initializeTinyML()) {
    Serial.println(
        "FATAL: TinyML initialization failed. Check model_data.h."
    );

    while (true) {
      delay(1000);
    }
  }

  Serial.println();
  Serial.println("Device ready.");
  Serial.println("Humidity threshold: > 70% = HIGH_HUMIDITY");
  Serial.println("Sampling interval: 2 seconds");
  Serial.println("Upload interval: 5 seconds");

  Serial.print("Device ID: ");
  Serial.println(DEVICE_ID);

  Serial.print("Server URL: ");
  Serial.println(SERVER_URL);

  Serial.println(
      "Both NORMAL and HIGH_HUMIDITY readings will be sent."
  );
}

// =====================================================
// MAIN LOOP
// =====================================================

void loop() {
  static unsigned long lastSample = 0;
  static unsigned long lastUpload = 0;

  const unsigned long now = millis();

  // Sample approximately every 2 seconds without
  // using a long delay that blocks reconnection.
  if (now - lastSample < SAMPLE_INTERVAL_MS) {
    delay(10);
    return;
  }

  lastSample = now;

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
  // PREPROCESS FEATURES FOR TINYML
  // -----------------------------------------------

  // Keep preprocessing consistent with the existing
  // model's training configuration.
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

  // -----------------------------------------------
  // PRINT SENSOR READINGS
  // -----------------------------------------------

  Serial.println();
  Serial.println("------------------------------------");
  Serial.println("SENSOR AND TINYML RESULTS");
  Serial.println("------------------------------------");

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
  // RUN TINYML MODEL
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

  // Existing model mapping:
  // 0 = NORMAL
  // 1 = HIGH_HUMIDITY
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
  // APPLY THE EXPLICIT 70% THRESHOLD
  // -----------------------------------------------

  // This threshold rule takes priority over the
  // TinyML prediction when selecting the final label.
  const char* finalLabel =
      (humidity > HUMIDITY_THRESHOLD)
          ? "HIGH_HUMIDITY"
          : "NORMAL";

  Serial.print("Final prediction: ");
  Serial.println(finalLabel);

  if (strcmp(finalLabel, "HIGH_HUMIDITY") == 0) {
    Serial.println(
        "!!! HIGH HUMIDITY ANOMALY DETECTED !!!"
    );
  } else {
    Serial.println("Humidity is within the normal range.");
  }

  // -----------------------------------------------
  // UPLOAD AT THE CONFIGURED INTERVAL
  // -----------------------------------------------

  const unsigned long uploadNow = millis();

  if (
      lastUpload == 0 ||
      uploadNow - lastUpload >= UPLOAD_INTERVAL_MS
  ) {
    Serial.println();
    Serial.println("Uploading sensor reading...");

    const bool uploaded = sendToServer(
        temperature,
        humidity,
        finalLabel
    );

    if (uploaded) {
      lastUpload = millis();

      Serial.println("Upload completed successfully.");
    } else {
      // Do not mark the upload as successful.
      // Retry on the next sample instead of waiting
      // another full upload interval.
      Serial.println(
          "Upload unsuccessful. Will retry on a later sample."
      );
    }
  }

  // -----------------------------------------------
  // LOCAL DIAGNOSTIC OUTPUT
  // -----------------------------------------------

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
}