#include "esp_camera.h"
#include <WiFi.h>
#include <HTTPClient.h>
#include <ESP32_CAM_TinyML_Security_inferencing.h>
#include "edge-impulse-sdk/dsp/image/image.hpp"

#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h" 
#include "esp_heap_caps.h"

#include <cstring>
#include <cstdlib>
#include <cmath>

// Stops at the first step that corrupts the heap.
#define HEAP_CHECK(tag) do { \
    if (!heap_caps_check_integrity_all(true)) { \
        Serial.printf("HEAP CORRUPTED after: %s\n", tag); \
        while (true) delay(1000); \
    } \
} while (0)

#if defined(SET_LOOP_TASK_STACK_SIZE)
SET_LOOP_TASK_STACK_SIZE(16 * 1024);
#endif

// ============================================================
// AI-THINKER ESP32-CAM CAMERA PINS
// ============================================================

#define PWDN_GPIO_NUM     32
#define RESET_GPIO_NUM    -1
#define XCLK_GPIO_NUM      0
#define SIOD_GPIO_NUM     26
#define SIOC_GPIO_NUM     27

#define Y9_GPIO_NUM       35
#define Y8_GPIO_NUM       34
#define Y7_GPIO_NUM       39
#define Y6_GPIO_NUM       36
#define Y5_GPIO_NUM       21
#define Y4_GPIO_NUM       19
#define Y3_GPIO_NUM       18
#define Y2_GPIO_NUM        5

#define VSYNC_GPIO_NUM    25
#define HREF_GPIO_NUM     23
#define PCLK_GPIO_NUM     22

// ============================================================
// WI-FI AND FLASK CONFIGURATION
// ============================================================

// Replace these placeholders locally. Do not share your password.
const char *WIFI_SSID = "ICSB";
const char *WIFI_PASSWORD = "PASSWORD";

// Windows host IP and Flask endpoint.
const char *FLASK_URL =
    "http://172.21.1.237:5000/api/camera-event";

const char *FLASK_IMAGE_URL =
    "http://172.21.1.237:5000/api/camera-image";
const char *CAMERA_DEVICE_ID = "ESP32-CAM";

WiFiServer previewServer(80);
bool previewServerReady = false;

// ============================================================
// SETTINGS
// ============================================================

#define FRAME_WIDTH   160
#define FRAME_HEIGHT  120
#define BYTE_STEP 8
#define BYTE_DIFFERENCE_THRESHOLD 15

bool SECURITY_MODE = true;

const float PERSON_CONFIDENCE_THRESHOLD = 0.60f;
const int REQUIRED_PERSON_FRAMES = 2;

// ============================================================
// FRAME MEMORY
// ============================================================

const size_t FRAME_BYTES = FRAME_WIDTH * FRAME_HEIGHT * 2;

uint8_t *previousFrame = nullptr;

static const uint32_t EI_RAW_WIDTH = 160;
static const uint32_t EI_RAW_HEIGHT = 120;

uint8_t *rgb888_buf = nullptr;
uint8_t *model_buf = nullptr;

float lastMotionScore = 0.0f;

// ============================================================
// AES-256-GCM CONFIGURATION
// ============================================================

// Demonstration key only.
// For deployment, use securely provisioned, unique device keys.
const unsigned char AES_KEY[32] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

// A new 12-byte nonce is generated for every encryption.
unsigned char AES_NONCE[12] = {0};

// ============================================================
// CAMERA INITIALIZATION — AI-THINKER ESP32-CAM
// Uses the camera pin assignments from your original sketch.
// ============================================================

bool initCamera()
{
    camera_config_t config = {};

    config.ledc_channel = LEDC_CHANNEL_0;
    config.ledc_timer   = LEDC_TIMER_0;

    // Camera data pins — preserve your original assignments
    config.pin_d0 = Y2_GPIO_NUM;
    config.pin_d1 = Y3_GPIO_NUM;
    config.pin_d2 = Y4_GPIO_NUM;
    config.pin_d3 = Y5_GPIO_NUM;
    config.pin_d4 = Y6_GPIO_NUM;
    config.pin_d5 = Y7_GPIO_NUM;
    config.pin_d6 = Y8_GPIO_NUM;
    config.pin_d7 = Y9_GPIO_NUM;

    // Camera control pins
    config.pin_xclk  = XCLK_GPIO_NUM;
    config.pin_pclk  = PCLK_GPIO_NUM;
    config.pin_vsync = VSYNC_GPIO_NUM;
    config.pin_href  = HREF_GPIO_NUM;

    config.pin_sccb_sda = SIOD_GPIO_NUM;
    config.pin_sccb_scl = SIOC_GPIO_NUM;

    config.pin_pwdn  = PWDN_GPIO_NUM;
    config.pin_reset = RESET_GPIO_NUM;

    // Camera clock
    config.xclk_freq_hz = 20000000;

    // Preserve your original image format and resolution
    config.pixel_format = PIXFORMAT_RGB565;
    config.frame_size   = FRAMESIZE_QQVGA;
    config.jpeg_quality = 12;

    // Frame buffer configuration
    config.fb_count   = 1;
    config.grab_mode  = CAMERA_GRAB_WHEN_EMPTY;
    config.fb_location = CAMERA_FB_IN_DRAM;

    // Initialize camera
    esp_err_t err = esp_camera_init(&config);

    if (err != ESP_OK)
    {
        Serial.printf(
            "Camera initialization failed: 0x%x\n",
            err
        );

        return false;
    }

    Serial.println("AI-THINKER ESP32-CAM initialized successfully.");

    return true;
}

// ============================================================
// MOTION SCORE
// ============================================================

float calculateMotion(camera_fb_t *fb)
{
    if (fb == nullptr || previousFrame == nullptr) {
        return 0.0f;
    }

    uint8_t *current = fb->buf;
    size_t changedBytes = 0;
    size_t totalBytes = 0;

    for (size_t i = 0; i < fb->len && i < FRAME_BYTES; i += BYTE_STEP) {
        int difference =
            abs((int)current[i] - (int)previousFrame[i]);

        if (difference >= BYTE_DIFFERENCE_THRESHOLD) {
            changedBytes++;
        }

        totalBytes++;
    }

    if (totalBytes == 0) return 0.0f;

    return ((float)changedBytes / (float)totalBytes) * 100.0f;
}

void saveCurrentFrame(camera_fb_t *fb)
{
    if (fb == nullptr || previousFrame == nullptr) return;

    memcpy(previousFrame, fb->buf, FRAME_BYTES);
}

// ============================================================
// SHA-256
// ============================================================

String calculateSHA256(const String &data)
{
    unsigned char hash[32];
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(
        &ctx,
        (const unsigned char *)data.c_str(),
        data.length()
    );
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    String result;
    char buffer[3];

    for (int i = 0; i < 32; i++) {
        snprintf(buffer, sizeof(buffer), "%02x", hash[i]);
        result += buffer;
    }

    return result;
}

// ============================================================
// BASE64 ENCODING
// ============================================================

String toBase64(const unsigned char *data, size_t length)
{
    size_t outputLength = 0;
    size_t capacity = 4 * ((length + 2) / 3) + 1;

    unsigned char *output =
        (unsigned char *)malloc(capacity);

    if (output == nullptr) {
        Serial.println("ERROR: Base64 allocation failed.");
        return "";
    }

    int ret = mbedtls_base64_encode(
        output,
        capacity,
        &outputLength,
        data,
        length
    );

    if (ret != 0) {
        Serial.printf("Base64 encoding failed: %d\n", ret);
        free(output);
        return "";
    }

    String result;
    result.reserve(outputLength);

    for (size_t i = 0; i < outputLength; i++) {
        result += (char)output[i];
    }

    free(output);
    return result;
}

// ============================================================
// AES-256-GCM ENCRYPTION
// ============================================================

bool encryptAESGCM(
    const String &plaintext,
    String &nonceBase64,
    String &ciphertextBase64,
    String &tagBase64)
{
    const size_t plaintextLength = plaintext.length();

    unsigned char *ciphertext =
        (unsigned char *)malloc(plaintextLength + 1);

    if (ciphertext == nullptr) {
        Serial.println("ERROR: Ciphertext allocation failed.");
        return false;
    }

    unsigned char tag[16];

    // Fresh random 96-bit nonce.
    for (size_t i = 0; i < sizeof(AES_NONCE); i++) {
        AES_NONCE[i] =
            (unsigned char)(esp_random() & 0xFF);
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(
        &gcm,
        MBEDTLS_CIPHER_ID_AES,
        AES_KEY,
        256
    );

    if (ret != 0) {
        Serial.printf("GCM setkey failed: %d\n", ret);
        mbedtls_gcm_free(&gcm);
        free(ciphertext);
        return false;
    }

    // This MUST match Flask's device_id.encode("utf-8").
    const unsigned char *aad =
        (const unsigned char *)CAMERA_DEVICE_ID;

    const size_t aadLength = strlen(CAMERA_DEVICE_ID);

    ret = mbedtls_gcm_crypt_and_tag(
        &gcm,
        MBEDTLS_GCM_ENCRYPT,
        plaintextLength,
        AES_NONCE,
        sizeof(AES_NONCE),
        aad,
        aadLength,
        (const unsigned char *)plaintext.c_str(),
        ciphertext,
        sizeof(tag),
        tag
    );

    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        Serial.printf("GCM encryption failed: %d\n", ret);
        free(ciphertext);
        return false;
    }

    nonceBase64 = toBase64(
        AES_NONCE, sizeof(AES_NONCE));

    ciphertextBase64 = toBase64(
        ciphertext, plaintextLength);

    tagBase64 = toBase64(
        tag, sizeof(tag));

    free(ciphertext);

    return nonceBase64.length() > 0 &&
           ciphertextBase64.length() > 0 &&
           tagBase64.length() > 0;
}

// ============================================================
// SEND ENCRYPTED EVENT TO FLASK
// ============================================================

// Flask needs up to ~8 seconds for the Cloudinary + Fabric steps.
const int HTTP_RESPONSE_TIMEOUT_MS = 30000;

// Returns true when Flask answers with a 2xx status. The reply text is
// stored in responseBody so the caller can read the new event ID.
bool sendEncryptedEvent(
    const String &nonceBase64,
    const String &ciphertextBase64,
    const String &tagBase64,
    String &responseBody)
{
    responseBody = "";

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("ERROR: Wi-Fi disconnected; event not sent.");
        return false;
    }

    HTTPClient http;

    if (!http.begin(FLASK_URL)) {
        Serial.println("ERROR: Could not initialize HTTP connection.");
        return false;
    }

    http.setConnectTimeout(5000);
    http.setTimeout(HTTP_RESPONSE_TIMEOUT_MS);
    http.addHeader("Content-Type", "application/json");

    // The Flask endpoint expects these four fields.
    String payload;
    payload.reserve(
        nonceBase64.length() +
        ciphertextBase64.length() +
        tagBase64.length() + 100
    );

    payload = "{\"device_id\":\"";
    payload += CAMERA_DEVICE_ID;
    payload += "\",\"nonce\":\"";
    payload += nonceBase64;
    payload += "\",\"ciphertext\":\"";
    payload += ciphertextBase64;
    payload += "\",\"tag\":\"";
    payload += tagBase64;
    payload += "\"}";

    Serial.println("Sending encrypted event to Flask...");

    int httpCode = http.POST(payload);

    bool success = (httpCode >= 200 && httpCode < 300);

    if (httpCode > 0) {
        Serial.printf("Flask HTTP status: %d\n", httpCode);

        responseBody = http.getString();
        Serial.println("Flask response:");
        Serial.println(responseBody);
    } else {
        Serial.printf(
            "HTTP request failed: %s\n",
            http.errorToString(httpCode).c_str()
        );
    }

    http.end();
    return success;
}

// ============================================================
// ENCRYPTED ANOMALY IMAGE
// The JPEG is encrypted on the device with the same AES-256-GCM
// camera key. The event ID is bound into the authenticated data
// (AAD) so the image cannot be attached to a different event.
// ============================================================

// Reads "key":"value" from a small JSON reply. Returns "" if missing.
String jsonStringValue(const String &body, const char *key)
{
    String needle = String("\"") + key + "\"";

    int k = body.indexOf(needle);
    if (k < 0) return "";

    int colon = body.indexOf(':', k + (int)needle.length());
    if (colon < 0) return "";

    int start = body.indexOf('"', colon + 1);
    if (start < 0) return "";

    int end = body.indexOf('"', start + 1);
    if (end < 0) return "";

    return body.substring(start + 1, end);
}

bool encryptBytesAESGCM(
    const unsigned char *plain,
    size_t plainLength,
    const String &aadText,
    String &nonceBase64,
    String &ciphertextBase64,
    String &tagBase64)
{
    unsigned char *ciphertext =
        (unsigned char *)malloc(plainLength + 1);

    if (ciphertext == nullptr) {
        Serial.println("ERROR: Image ciphertext allocation failed.");
        return false;
    }

    unsigned char nonce[12];
    unsigned char tag[16];

    // Fresh random 96-bit nonce for every image.
    for (size_t i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (unsigned char)(esp_random() & 0xFF);
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(
        &gcm,
        MBEDTLS_CIPHER_ID_AES,
        AES_KEY,
        256
    );

    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(
            &gcm,
            MBEDTLS_GCM_ENCRYPT,
            plainLength,
            nonce,
            sizeof(nonce),
            (const unsigned char *)aadText.c_str(),
            aadText.length(),
            plain,
            ciphertext,
            sizeof(tag),
            tag
        );
    }

    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        Serial.printf("Image GCM encryption failed: %d\n", ret);
        free(ciphertext);
        return false;
    }

    nonceBase64 = toBase64(nonce, sizeof(nonce));
    ciphertextBase64 = toBase64(ciphertext, plainLength);
    tagBase64 = toBase64(tag, sizeof(tag));

    free(ciphertext);

    return nonceBase64.length() > 0 &&
           ciphertextBase64.length() > 0 &&
           tagBase64.length() > 0;
}

bool sendEncryptedImage(const String &cameraEventId)
{
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("ERROR: Wi-Fi disconnected; image not sent.");
        return false;
    }

    // Take a fresh frame at the moment of detection.
    camera_fb_t *fb = esp_camera_fb_get();

    if (fb == nullptr) {
        Serial.println("ERROR: Could not capture the anomaly image.");
        return false;
    }

    uint8_t *jpg = nullptr;
    size_t jpgLength = 0;

    const bool converted = frame2jpg(fb, 80, &jpg, &jpgLength);

    esp_camera_fb_return(fb);

    if (!converted || jpg == nullptr || jpgLength == 0) {
        if (jpg != nullptr) free(jpg);
        Serial.println("ERROR: JPEG conversion failed.");
        return false;
    }

    Serial.printf("Anomaly image: JPEG %u bytes\n", (unsigned)jpgLength);

    String aad = String("ESP32-CAM:IMAGE:") + cameraEventId;

    String nonceBase64;
    String ciphertextBase64;
    String tagBase64;

    const bool encrypted = encryptBytesAESGCM(
        jpg,
        jpgLength,
        aad,
        nonceBase64,
        ciphertextBase64,
        tagBase64
    );

    free(jpg);

    if (!encrypted) {
        Serial.println("ERROR: Image encryption failed; image not sent.");
        return false;
    }

    Serial.println("Image encrypted with AES-256-GCM.");

    HTTPClient http;

    if (!http.begin(FLASK_IMAGE_URL)) {
        Serial.println("ERROR: Could not initialize image HTTP connection.");
        return false;
    }

    http.setConnectTimeout(5000);
    http.setTimeout(HTTP_RESPONSE_TIMEOUT_MS);
    http.addHeader("Content-Type", "application/json");

    String payload;
    payload.reserve(
        nonceBase64.length() +
        ciphertextBase64.length() +
        tagBase64.length() + 160
    );

    payload = "{\"device_id\":\"";
    payload += CAMERA_DEVICE_ID;
    payload += "\",\"camera_event_id\":\"";
    payload += cameraEventId;
    payload += "\",\"nonce\":\"";
    payload += nonceBase64;
    payload += "\",\"ciphertext\":\"";
    payload += ciphertextBase64;
    payload += "\",\"tag\":\"";
    payload += tagBase64;
    payload += "\"}";

    Serial.println("Sending encrypted image to Flask...");

    int httpCode = http.POST(payload);

    bool success = (httpCode >= 200 && httpCode < 300);

    if (httpCode > 0) {
        Serial.printf("Flask image HTTP status: %d\n", httpCode);

        String response = http.getString();
        Serial.println("Flask image response:");
        Serial.println(response);
    } else {
        Serial.printf(
            "Image HTTP request failed: %s\n",
            http.errorToString(httpCode).c_str()
        );
    }

    http.end();
    return success;
}

// ============================================================
// GENERATE AND TRANSMIT INTRUSION EVENT
// ============================================================

void generateIntrusionEvent(
    float motionScore,
    float personConfidence)
{
    Serial.println();
    Serial.println("========================================");
    Serial.println("       PERSON DETECTION EVENT");
    Serial.println("========================================");

    // Person detection while armed triggers the configured event.
    // It does not independently prove unauthorized entry.
    String eventJson = "{";

    eventJson += "\"event_type\":\"INTRUSION\",";
    eventJson += "\"source\":\"ESP32-CAM\",";
    eventJson += "\"detection\":\"TINYML_PERSON_CLASSIFIER\",";
    eventJson += "\"security_mode\":\"ARMED\",";
    eventJson += "\"context\":\"PROTECTED_HOME\",";
    eventJson += "\"motion_score\":";
    eventJson += String(motionScore, 2);
    eventJson += ",\"person_confidence\":";
    eventJson += String(personConfidence, 4);
    eventJson += ",\"status\":\"ANOMALY\"";
    eventJson += "}";

    Serial.println("Event created.");

    // Hash is calculated locally for integrity demonstration.
    String hash = calculateSHA256(eventJson);

    Serial.print("Plaintext SHA-256: ");
    Serial.println(hash);

    String nonceBase64;
    String ciphertextBase64;
    String tagBase64;

    if (!encryptAESGCM(
            eventJson,
            nonceBase64,
            ciphertextBase64,
            tagBase64)) {
        Serial.println("ERROR: Encryption failed; event not sent.");
        return;
    }

    Serial.println("AES-256-GCM encryption successful.");
    Serial.println("Nonce, ciphertext, and tag encoded in Base64.");

    String eventResponse;

    bool sent = sendEncryptedEvent(
        nonceBase64,
        ciphertextBase64,
        tagBase64,
        eventResponse
    );

    if (sent) {
        Serial.println("Flask accepted the HTTP request.");

        // The image is linked to the event Flask just created.
        String cameraEventId = jsonStringValue(eventResponse, "event_id");

        if (cameraEventId.length() != 36 ||
            !cameraEventId.startsWith("cam_")) {
            cameraEventId = "none";
        }

        Serial.print("Camera event ID: ");
        Serial.println(cameraEventId);

        Serial.println("Capturing and sending the anomaly image...");

        if (sendEncryptedImage(cameraEventId)) {
            Serial.println("Flask accepted the encrypted anomaly image.");
        } else {
            Serial.println(
                "Anomaly image was NOT stored (the event itself was recorded)."
            );
        }
    } else {
        Serial.println("Event transmission failed; image not sent.");
    }

    Serial.println("========================================");
}

// ============================================================
// LIVE PREVIEW OVER HTTP (BMP)
// /         -> preview page
// /capture  -> camera frame
// /model    -> TinyML model input
// ============================================================

static void writeU16(WiFiClient &client, uint16_t value)
{
    uint8_t bytes[2] = {
        (uint8_t)(value & 0xff),
        (uint8_t)(value >> 8)
    };

    client.write(bytes, sizeof(bytes));
}

static void writeU32(WiFiClient &client, uint32_t value)
{
    uint8_t bytes[4] = {
        (uint8_t)value,
        (uint8_t)(value >> 8),
        (uint8_t)(value >> 16),
        (uint8_t)(value >> 24)
    };

    client.write(bytes, sizeof(bytes));
}

static void sendBmpHeaders(
    WiFiClient &client,
    uint32_t w,
    uint32_t h,
    uint32_t dataSize)
{
    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: image/bmp");
    client.println("Cache-Control: no-store, no-cache, must-revalidate");
    client.print("Content-Length: ");
    client.println(54 + dataSize);
    client.println("Connection: close");
    client.println();

    client.write((const uint8_t *)"BM", 2);

    writeU32(client, 54 + dataSize);
    writeU16(client, 0);
    writeU16(client, 0);
    writeU32(client, 54);
    writeU32(client, 40);
    writeU32(client, w);
    writeU32(client, h);
    writeU16(client, 1);
    writeU16(client, 24);
    writeU32(client, 0);
    writeU32(client, dataSize);
    writeU32(client, 2835);
    writeU32(client, 2835);
    writeU32(client, 0);
    writeU32(client, 0);
}

static void sendPreviewBmp(WiFiClient &client)
{
    camera_fb_t *fb = esp_camera_fb_get();

    if (!fb ||
        fb->format != PIXFORMAT_RGB565 ||
        fb->width > FRAME_WIDTH) {
        if (fb) esp_camera_fb_return(fb);

        client.println(
            "HTTP/1.1 503 Service Unavailable\r\n"
            "Connection: close\r\n\r\n"
            "Camera capture failed"
        );
        return;
    }

    const uint16_t w = fb->width;
    const uint16_t h = fb->height;

    const uint32_t rowBytes =
        ((uint32_t)w * 3 + 3) & ~3U;

    const uint32_t dataSize = rowBytes * h;

    sendBmpHeaders(client, w, h, dataSize);

    uint8_t row[FRAME_WIDTH * 3 + 4];

    for (int y = (int)h - 1;
         y >= 0 && client.connected();
         --y) {

        uint32_t out = 0;

        for (uint16_t x = 0; x < w; ++x) {
            size_t i = ((size_t)y * w + x) * 2;

            uint16_t px =
                ((uint16_t)fb->buf[i] << 8) |
                fb->buf[i + 1];

            uint8_t r = (px >> 11) & 0x1f;
            uint8_t g = (px >> 5) & 0x3f;
            uint8_t b = px & 0x1f;

            row[out++] = (b << 3) | (b >> 2);
            row[out++] = (g << 2) | (g >> 4);
            row[out++] = (r << 3) | (r >> 2);
        }

        while (out < rowBytes) row[out++] = 0;

        client.write(row, rowBytes);
    }

    esp_camera_fb_return(fb);
}

static void sendModelBmp(WiFiClient &client)
{
    const uint32_t w = EI_CLASSIFIER_INPUT_WIDTH;
    const uint32_t h = EI_CLASSIFIER_INPUT_HEIGHT;

    const uint32_t rowBytes = (w * 3 + 3) & ~3U;
    const uint32_t dataSize = rowBytes * h;

    const uint8_t pad[4] = {0, 0, 0, 0};

    sendBmpHeaders(client, w, h, dataSize);

    for (int y = (int)h - 1;
         y >= 0 && client.connected();
         --y) {

        client.write(
            model_buf + (size_t)y * w * 3,
            w * 3
        );

        if (rowBytes > w * 3) {
            client.write(pad, rowBytes - w * 3);
        }
    }
}

static void handlePreviewClient()
{
    if (!previewServerReady) return;

    WiFiClient client = previewServer.available();
    if (!client) return;

    client.setTimeout(1200);

    String request = client.readStringUntil('\n');
    request.trim();

    while (client.connected()) {
        String line = client.readStringUntil('\n');

        if (line == "\r" || line.length() == 0) break;
    }

    if (request.indexOf("GET /capture") >= 0) {
        sendPreviewBmp(client);
    } else if (request.indexOf("GET /model") >= 0) {
        sendModelBmp(client);
    } else {
        const char page[] = R"rawliteral(
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32-CAM TinyML Preview</title>
<style>
body{font-family:Arial;margin:18px;background:#111;color:#eee}
.row{display:flex;gap:16px;flex-wrap:wrap}
figure{margin:0}
img{width:320px;height:auto;image-rendering:pixelated;
border:1px solid #777;background:#222}
figcaption,p{color:#ccc}
</style>
</head>
<body>
<h2>ESP32-CAM Live View + TinyML</h2>
<p>Left: camera frame. Right: model input. Scores are in Serial Monitor.</p>
<div class="row">
<figure>
<img id="cam" alt="Camera preview">
<figcaption>Camera</figcaption>
</figure>
<figure>
<img id="mdl" alt="TinyML model input">
<figcaption>Model input</figcaption>
</figure>
</div>
<p id="status">Loading...</p>
<script>
const st=document.getElementById('status');

async function load(id,url){
  const r=await fetch(url+'?t='+Date.now(),{cache:'no-store'});
  if(!r.ok)throw Error('HTTP '+r.status);
  const b=await r.blob();
  const im=document.getElementById(id);
  const old=im.src;
  im.onload=()=>{if(old.startsWith('blob:'))URL.revokeObjectURL(old);};
  im.src=URL.createObjectURL(b);
}

async function tick(){
  try{
    await load('cam','/capture');
    await load('mdl','/model');
    st.textContent='Preview updating';
  }catch(e){
    st.textContent='Preview error: '+e.message;
  }finally{
    setTimeout(tick,1000);
  }
}
tick();
</script>
</body>
</html>
)rawliteral";

        client.println("HTTP/1.1 200 OK");
        client.println("Content-Type: text/html; charset=utf-8");
        client.println("Cache-Control: no-store");
        client.println("Connection: close");
        client.println();
        client.print(page);
    }

    delay(1);
    client.stop();
}

static void startPreviewWiFi()
{
    if (String(WIFI_SSID) == "YOUR_WIFI_NAME" ||
        String(WIFI_PASSWORD) == "YOUR_WIFI_PASSWORD") {
        Serial.println("Edit Wi-Fi credentials before connecting.");
        return;
    }

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    Serial.print("Connecting to Wi-Fi");

    unsigned long start = millis();

    while (WiFi.status() != WL_CONNECTED &&
           millis() - start < 20000) {
        delay(400);
        Serial.print(".");
    }

    Serial.println();

    if (WiFi.status() == WL_CONNECTED) {
        WiFi.setTxPower(WIFI_POWER_11dBm);
        Serial.print("ESP32-CAM IP: ");
        Serial.println(WiFi.localIP());

        previewServer.begin();
        previewServerReady = true;

        Serial.println("Live preview server started on port 80.");
        Serial.print("Flask endpoint: ");
        Serial.println(FLASK_URL);
    } else {
        Serial.println("Wi-Fi timeout; preview and HTTP transmission unavailable.");
    }
}

// ============================================================
// SETUP
// ============================================================

void setup()
{
    Serial.begin(115200);
    delay(1000);

    Serial.println();
    Serial.println("========================================");
    Serial.println(" ESP32-CAM SECURE EDGE INTRUSION DEMO");
    Serial.println("========================================");

    Serial.println("Initializing camera...");

    if (!initCamera()) {
        Serial.println("CAMERA INITIALIZATION FAILED");
        while (true) delay(1000);
    }

    Serial.println("Camera initialization successful.");

    startPreviewWiFi();

    sensor_t *sensor = esp_camera_sensor_get();

    if (sensor != nullptr) {
        Serial.printf("Camera PID: 0x%02X\n", sensor->id.PID);
        Serial.printf("Camera VER: 0x%02X\n", sensor->id.VER);
    }

    Serial.printf(
        "PSRAM found: %d, free PSRAM: %u\n",
        (int)psramFound(),
        (unsigned)ESP.getFreePsram()
    );

    Serial.printf(
        "Free heap: %u, largest block: %u\n",
        (unsigned)ESP.getFreeHeap(),
        (unsigned)ESP.getMaxAllocHeap()
    );

    auto allocBuf = [](size_t n) -> uint8_t * {
        uint8_t *p = nullptr;

        if (psramFound()) {
            p = (uint8_t *)heap_caps_malloc(
                n,
                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT
            );
        }

        if (p == nullptr) p = (uint8_t *)malloc(n);

        return p;
    };

    previousFrame = allocBuf(FRAME_BYTES);
    rgb888_buf = allocBuf(EI_RAW_WIDTH * EI_RAW_HEIGHT * 3);

    model_buf = allocBuf(
        EI_CLASSIFIER_INPUT_WIDTH *
        EI_CLASSIFIER_INPUT_HEIGHT * 3
    );

    HEAP_CHECK("alloc");

    if (previousFrame == nullptr ||
        rgb888_buf == nullptr ||
        model_buf == nullptr) {
        Serial.println("ERROR: Camera/TinyML buffer allocation failed.");
        while (true) delay(1000);
    }

    memset(
        model_buf,
        0,
        EI_CLASSIFIER_INPUT_WIDTH *
        EI_CLASSIFIER_INPUT_HEIGHT * 3
    );

    Serial.printf(
        "Previous frame buffer: %u bytes\n",
        (unsigned)FRAME_BYTES
    );

    Serial.printf(
        "RGB888 buffer: %u bytes\n",
        (unsigned)(EI_RAW_WIDTH * EI_RAW_HEIGHT * 3)
    );

    Serial.printf(
        "TinyML input: %dx%d (%u bytes)\n",
        (int)EI_CLASSIFIER_INPUT_WIDTH,
        (int)EI_CLASSIFIER_INPUT_HEIGHT,
        (unsigned)(
            EI_CLASSIFIER_INPUT_WIDTH *
            EI_CLASSIFIER_INPUT_HEIGHT * 3
        )
    );

    Serial.print("Model labels:");

    for (uint16_t i = 0; i < EI_CLASSIFIER_LABEL_COUNT; i++) {
        Serial.printf(" [%s]", ei_classifier_inferencing_categories[i]);
    }

    Serial.println();

    camera_fb_t *fb = esp_camera_fb_get();

    if (fb == nullptr) {
        Serial.println("ERROR: Initial frame capture failed.");
        while (true) delay(1000);
    }

    if (fb->len < FRAME_BYTES) {
        Serial.println("ERROR: Initial frame is too small.");
        esp_camera_fb_return(fb);
        while (true) delay(1000);
    }

    memcpy(previousFrame, fb->buf, FRAME_BYTES);
    esp_camera_fb_return(fb);

    Serial.println("----------------------------------------");
    Serial.println("Security mode: ARMED");
    Serial.println("TinyML person classifier: ENABLED");
    Serial.printf(
        "Temporal confirmation: %d predictions\n",
        REQUIRED_PERSON_FRAMES
    );
    Serial.printf(
        "Person confidence threshold: %.2f\n",
        PERSON_CONFIDENCE_THRESHOLD
    );
    Serial.println("Integrity: SHA-256");
    Serial.println("Encryption: AES-256-GCM");
    Serial.println("Transport: HTTP POST");
    Serial.println("----------------------------------------");
    Serial.println("Monitoring for person detections...");
}

// ============================================================
// EDGE IMPULSE CAMERA CAPTURE AND PREPROCESSING
// ============================================================

static void cropResizeBGR(
    const uint8_t *src,
    uint32_t sw,
    uint32_t sh,
    uint8_t *dst,
    uint32_t dw,
    uint32_t dh)
{
    uint32_t cw = sw;
    uint32_t ch = sh;

    if ((uint64_t)sw * dh > (uint64_t)sh * dw) {
        cw = (sh * dw) / dh;
    } else {
        ch = (sw * dh) / dw;
    }

    uint32_t x0 = (sw - cw) / 2;
    uint32_t y0 = (sh - ch) / 2;

    for (uint32_t y = 0; y < dh; y++) {
        uint32_t sy = y0 + (y * ch) / dh;

        for (uint32_t x = 0; x < dw; x++) {
            uint32_t sx = x0 + (x * cw) / dw;

            const uint8_t *p =
                src + ((size_t)sy * sw + sx) * 3;

            uint8_t *q =
                dst + ((size_t)y * dw + x) * 3;

            q[0] = p[0];
            q[1] = p[1];
            q[2] = p[2];
        }
    }
}

bool ei_camera_capture(
    uint32_t img_width,
    uint32_t img_height,
    uint8_t *out_buf)
{
    camera_fb_t *fb = esp_camera_fb_get();

    if (fb == nullptr) {
        Serial.println("ERROR: Camera capture failed.");
        return false;
    }

    lastMotionScore = calculateMotion(fb);

    if (fb->len >= FRAME_BYTES) {
        saveCurrentFrame(fb);
    }

    bool converted = fmt2rgb888(
        fb->buf,
        fb->len,
        PIXFORMAT_RGB565,
        rgb888_buf
    );

    esp_camera_fb_return(fb);

    if (!converted) {
        Serial.println("ERROR: RGB conversion failed.");
        return false;
    }

    HEAP_CHECK("fmt2rgb888");

    cropResizeBGR(
        rgb888_buf,
        EI_RAW_WIDTH,
        EI_RAW_HEIGHT,
        out_buf,
        img_width,
        img_height
    );

    HEAP_CHECK("crop");

    return true;
}

static int ei_camera_get_data(
    size_t offset,
    size_t length,
    float *out_ptr)
{
    size_t pixel_ix = offset * 3;

    for (size_t i = 0; i < length; i++) {
        out_ptr[i] =
            ((uint32_t)model_buf[pixel_ix + 2] << 16) |
            ((uint32_t)model_buf[pixel_ix + 1] << 8) |
            (uint32_t)model_buf[pixel_ix];

        pixel_ix += 3;
    }

    return 0;
}

// ============================================================
// MAIN LOOP: TINYML CLASSIFICATION + SECURE EVENT
// ============================================================

void loop()
{
    handlePreviewClient();

    static int consecutivePersonFrames = 0;
    static bool intrusionAlreadyReported = false;

    if (ei_sleep(5) != EI_IMPULSE_OK) {
        return;
    }

    ei::signal_t signal;

    signal.total_length =
        EI_CLASSIFIER_INPUT_WIDTH *
        EI_CLASSIFIER_INPUT_HEIGHT;

    signal.get_data = &ei_camera_get_data;

    if (!ei_camera_capture(
            EI_CLASSIFIER_INPUT_WIDTH,
            EI_CLASSIFIER_INPUT_HEIGHT,
            model_buf)) {
        delay(200);
        return;
    }

    ei_impulse_result_t result = { 0 };

    EI_IMPULSE_ERROR err =
        run_classifier(&signal, &result, false);

    HEAP_CHECK("classify");

    if (err != EI_IMPULSE_OK) {
        Serial.printf("TinyML inference failed: %d\n", err);
        delay(200);
        return;
    }

    float personConfidence = 0.0f;
    bool personLabelFound = false;

    Serial.println();
    Serial.println("TinyML predictions:");

    for (uint16_t i = 0; i < EI_CLASSIFIER_LABEL_COUNT; i++) {
        const char *label = ei_classifier_inferencing_categories[i];
        float confidence = result.classification[i].value;

        Serial.printf("  %s: %.4f\n", label, confidence);

        if (String(label).equalsIgnoreCase("person")) {
            personConfidence = confidence;
            personLabelFound = true;
        }
    }

    if (!personLabelFound) {
        Serial.println(
            "WARNING: No 'person' label found in the model."
        );
    }

    Serial.printf("Motion score: %.2f%%\n", lastMotionScore);

    Serial.printf(
        "Inference time: DSP %d ms, classification %d ms, anomaly %d ms\n",
        result.timing.dsp,
        result.timing.classification,
        result.timing.anomaly
    );

    if (personConfidence >= PERSON_CONFIDENCE_THRESHOLD) {
        consecutivePersonFrames++;

        Serial.printf(
            "Person candidate: %d/%d consecutive predictions\n",
            consecutivePersonFrames,
            REQUIRED_PERSON_FRAMES
        );
    } else {
        consecutivePersonFrames = 0;
        intrusionAlreadyReported = false;

        Serial.println("No person candidate above threshold.");
    }

    if (consecutivePersonFrames >= REQUIRED_PERSON_FRAMES) {
        if (SECURITY_MODE) {
            if (!intrusionAlreadyReported) {
                generateIntrusionEvent(
                    lastMotionScore,
                    personConfidence
                );

                intrusionAlreadyReported = true;
            }
        } else {
            Serial.println(
                "Security mode OFF; no intrusion event generated."
            );
        }

        consecutivePersonFrames = REQUIRED_PERSON_FRAMES;
    }

#if EI_CLASSIFIER_HAS_ANOMALY
    Serial.printf("Anomaly prediction: %.3f\n", result.anomaly);
#endif

    delay(100);
}

#if !defined(EI_CLASSIFIER_SENSOR) || \
    EI_CLASSIFIER_SENSOR != EI_CLASSIFIER_SENSOR_CAMERA
#error "Invalid model for current sensor"
#endif