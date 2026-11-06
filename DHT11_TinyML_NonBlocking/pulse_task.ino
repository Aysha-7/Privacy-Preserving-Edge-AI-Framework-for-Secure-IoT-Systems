// =====================================================
// HW-627 PULSE SENSOR (second tab of the DHT11 sketch)
//
// Wiring:  HW-627  VCC -> 3V3,  GND -> GND,  S (signal) -> GPIO 34
// GPIO 34 is on ADC1, which keeps working while Wi-Fi is on.
//
// Demo rule: finger on the sensor = ANOMALY (stand-in for an abnormal
// heart rate); no finger = NORMAL. The finger is recognised from the
// signal swing (max - min) over the last 2 seconds. This is a simple
// threshold rule, NOT a TinyML model.
//
// Uses the main tab's AES key, DEVICE_ID, SERVER_HOST/PORT and helpers.
// Runs in its own task so it never delays the DHT11 / TinyML loop.
// =====================================================

constexpr int PULSE_PIN = 34;
constexpr unsigned long PULSE_SAMPLE_MS = 20;        // 50 samples/second
constexpr int PULSE_WINDOW = 100;                    // last 2 seconds
constexpr int PULSE_FINGER_SWING = 300;              // <- copy the calibrated value here
constexpr bool PULSE_CALIBRATE_ON_BOOT = true;       // set to false after calibrating
// How a finger is recognised (calibration prints the right values):
//   0 = signal swing above PULSE_FINGER_SWING
//   1 = average level above/below PULSE_LEVEL_THRESHOLD
constexpr int PULSE_FINGER_MODE = 0;
constexpr int PULSE_LEVEL_THRESHOLD = 2700;
constexpr bool PULSE_LEVEL_ABOVE = true;
constexpr unsigned long PULSE_STABLE_MS = 3000UL;    // finger held this long
constexpr unsigned long PULSE_REPEAT_MS = 20000UL;   // repeat while held
constexpr unsigned long PULSE_RETRY_MS = 5000UL;
constexpr unsigned long PULSE_IDLE_REPORT_MS = 10000UL;
constexpr bool PULSE_CALIBRATION_PRINT = true;       // 1 line per second
const char* PULSE_PATH = "/api/pulse";

static bool buildPulseEnvelope(const String& plaintext, String& envelope) {
  uint8_t key[32];

  if (!hexKeyToBytes(AES_KEY_HEX, key)) {
    return false;
  }

  uint8_t nonce[12];
  uint8_t tag[16];

  for (int i = 0; i < 3; i++) {
    const uint32_t randomValue = esp_random();
    memcpy(nonce + (i * 4), &randomValue, 4);
  }

  const size_t length = plaintext.length();
  uint8_t* ciphertext = static_cast<uint8_t*>(malloc(length));

  if (ciphertext == nullptr) {
    memset(key, 0, sizeof(key));
    return false;
  }

  const bool encrypted = encryptPayload(
      key,
      nonce,
      DEVICE_ID,
      reinterpret_cast<const uint8_t*>(plaintext.c_str()),
      length,
      ciphertext,
      tag
  );

  memset(key, 0, sizeof(key));

  String nonceB64;
  String ciphertextB64;
  String tagB64;

  const bool encoded =
      encrypted &&
      base64Encode(nonce, sizeof(nonce), nonceB64) &&
      base64Encode(ciphertext, length, ciphertextB64) &&
      base64Encode(tag, sizeof(tag), tagB64);

  free(ciphertext);

  if (!encoded) {
    return false;
  }

  envelope = "{\"device_id\":\"";
  envelope += DEVICE_ID;
  envelope += "\",\"nonce\":\"";
  envelope += nonceB64;
  envelope += "\",\"ciphertext\":\"";
  envelope += ciphertextB64;
  envelope += "\",\"tag\":\"";
  envelope += tagB64;
  envelope += "\"}";

  return true;
}

// Returns the HTTP status code, or 0 on a transport failure.
static int postPulse(const String& envelope, String& body) {
  WiFiClient client;

  if (!client.connect(SERVER_HOST, SERVER_PORT, TCP_CONNECT_TIMEOUT_MS)) {
    Serial.println("[PULSE] TCP connect failed.");
    return 0;
  }

  HTTPClient http;

  http.setReuse(false);
  http.setTimeout(HTTP_RESPONSE_TIMEOUT_MS);

  if (!http.begin(client, SERVER_HOST, SERVER_PORT, PULSE_PATH)) {
    client.stop();
    return 0;
  }

  http.addHeader("Content-Type", "application/json");

  const int code = http.POST(envelope);

  if (code > 0) {
    body = http.getString();
  }

  http.end();

  return code > 0 ? code : 0;
}

static bool sendPulseReport(
    bool anomaly,
    int bpm,
    const int* ring,
    int head
) {
  String plaintext;
  plaintext.reserve(anomaly ? 800 : 160);

  plaintext = "{\"device_id\":\"";
  plaintext += DEVICE_ID;
  plaintext += "\",\"sensor\":\"HW-627\",\"status\":\"";
  plaintext += anomaly ? "ANOMALY" : "NORMAL";
  plaintext += "\",\"finger_detected\":";
  plaintext += anomaly ? "true" : "false";
  plaintext += ",\"bpm\":";
  plaintext += String(bpm);
  plaintext += ",\"sample_rate_hz\":50,\"waveform\":[";

  if (anomaly) {
    // Oldest sample first.
    for (int i = 0; i < PULSE_WINDOW; i++) {
      if (i > 0) {
        plaintext += ",";
      }

      plaintext += String(ring[(head + i) % PULSE_WINDOW]);
    }
  }

  plaintext += "]}";

  String envelope;

  if (!buildPulseEnvelope(plaintext, envelope)) {
    Serial.println("[PULSE] Encryption failed; report not sent.");
    return false;
  }

  String body;
  const int code = postPulse(envelope, body);

  if (code == 200 || code == 201) {
    if (anomaly) {
      Serial.printf(
          "[PULSE] ANOMALY accepted (HTTP %d): cloud=%s fabric=%s\n",
          code,
          jsonStringField(body, "cloud_storage_status").c_str(),
          jsonStringField(body, "fabric_status").c_str()
      );
    }

    return true;
  }

  Serial.printf("[PULSE] Server did not accept the report (HTTP %d).\n", code);

  if (code > 0) {
    Serial.println(body.substring(0, 120));
  }

  return false;
}

// Median of 5 quick reads: removes the short spikes that Wi-Fi activity
// puts on the ESP32 analog input.
static int readPulseMedian() {
  int v[5];

  for (int i = 0; i < 5; i++) {
    v[i] = analogRead(PULSE_PIN);
  }

  for (int i = 1; i < 5; i++) {
    const int key = v[i];
    int j = i - 1;
    while (j >= 0 && v[j] > key) { v[j + 1] = v[j]; j--; }
    v[j + 1] = key;
  }

  return v[2];
}

// "Robust swing": 90th minus 10th percentile of the last 2 seconds, so a
// single noise spike cannot fake a finger. Also returns the P10/P90 values.
static int robustSwing(const int* ring, int& p10, int& p90) {
  int s[PULSE_WINDOW];

  for (int i = 0; i < PULSE_WINDOW; i++) s[i] = ring[i];

  for (int i = 1; i < PULSE_WINDOW; i++) {
    const int key = s[i];
    int j = i - 1;
    while (j >= 0 && s[j] > key) { s[j + 1] = s[j]; j--; }
    s[j + 1] = key;
  }

  p10 = s[PULSE_WINDOW / 10];
  p90 = s[PULSE_WINDOW - 1 - PULSE_WINDOW / 10];

  return p90 - p10;
}

// Detection rule (set from the constants, or by calibration).
static int gRuleMode = PULSE_FINGER_MODE;
static int gRuleSwing = PULSE_FINGER_SWING;
static int gRuleLevel = PULSE_LEVEL_THRESHOLD;
static bool gRuleAbove = PULSE_LEVEL_ABOVE;

static int windowMean(const int* ring) {
  long sum = 0;
  for (int i = 0; i < PULSE_WINDOW; i++) sum += ring[i];
  return (int)(sum / PULSE_WINDOW);
}

// Boot-time calibration: 8 s without a finger, then 8 s with a finger.
// It compares both the swing and the average level, and prints the rule
// that separates the two cases.
static void calibratePulse() {
  int ring[PULSE_WINDOW];

  int swingLo[2] = {4095, 4095};
  int swingHi[2] = {0, 0};
  int meanLo[2] = {4095, 4095};
  int meanHi[2] = {0, 0};

  for (int phase = 0; phase < 2; phase++) {
    Serial.println();
    Serial.println(
        phase == 0
            ? "[CAL] KEEP YOUR FINGER OFF THE SENSOR. Starting in 5 s..."
            : "[CAL] NOW PLACE YOUR FINGER on the sensor (gentle, steady). Starting in 5 s..."
    );

    vTaskDelay(pdMS_TO_TICKS(5000));

    Serial.println("[CAL] Measuring for 8 s...");

    int filled = 0;
    int head = 0;
    unsigned long next = millis();
    const unsigned long end = millis() + 10000UL;
    unsigned long lastWindow = 0;

    while (millis() < end) {
      if (millis() < next) { vTaskDelay(pdMS_TO_TICKS(2)); continue; }
      next += PULSE_SAMPLE_MS;

      ring[head] = readPulseMedian();
      head = (head + 1) % PULSE_WINDOW;
      if (filled < PULSE_WINDOW) { filled++; continue; }

      if (millis() - lastWindow >= 1000UL) {
        lastWindow = millis();

        int p10, p90;
        const int swing = robustSwing(ring, p10, p90);
        const int mean = windowMean(ring);

        Serial.printf("[CAL] swing=%d level=%d\n", swing, mean);

        if (swing < swingLo[phase]) swingLo[phase] = swing;
        if (swing > swingHi[phase]) swingHi[phase] = swing;
        if (mean < meanLo[phase]) meanLo[phase] = mean;
        if (mean > meanHi[phase]) meanHi[phase] = mean;
      }
    }
  }

  Serial.println();
  Serial.printf("[CAL] No finger : swing %d..%d, level %d..%d\n",
                swingLo[0], swingHi[0], meanLo[0], meanHi[0]);
  Serial.printf("[CAL] With finger: swing %d..%d, level %d..%d\n",
                swingLo[1], swingHi[1], meanLo[1], meanHi[1]);

  // Prefer the average level when the two ranges do not overlap.
  if (meanLo[1] > meanHi[0] + 20) {
    gRuleMode = 1; gRuleLevel = (meanHi[0] + meanLo[1]) / 2; gRuleAbove = true;
  } else if (meanHi[1] < meanLo[0] - 20) {
    gRuleMode = 1; gRuleLevel = (meanHi[1] + meanLo[0]) / 2; gRuleAbove = false;
  } else if (swingLo[1] > swingHi[0] + 20) {
    gRuleMode = 0; gRuleSwing = (swingHi[0] + swingLo[1]) / 2;
  } else if (swingHi[1] < swingLo[0] - 20) {
    Serial.println("[CAL] Finger lowers the swing; level and swing both overlap.");
    Serial.println("[CAL] No reliable rule. Shade the sensor, shorten the wire, add 100 nF (S to GND), retry.");
    return;
  } else {
    Serial.println("[CAL] No clear difference. Check the wiring, shade the sensor, add 100 nF (S to GND), retry.");
    return;
  }

  if (gRuleMode == 1) {
    Serial.printf(
        "[CAL] >>> Set  PULSE_FINGER_MODE = 1;  PULSE_LEVEL_THRESHOLD = %d;  PULSE_LEVEL_ABOVE = %s;  PULSE_CALIBRATE_ON_BOOT = false; <<<\n",
        gRuleLevel, gRuleAbove ? "true" : "false");
  } else {
    Serial.printf(
        "[CAL] >>> Set  PULSE_FINGER_MODE = 0;  PULSE_FINGER_SWING = %d;  PULSE_CALIBRATE_ON_BOOT = false; <<<\n",
        gRuleSwing);
  }

}

static void pulseTask(void* parameter) {
  (void)parameter;

  if (PULSE_CALIBRATE_ON_BOOT) {
    vTaskDelay(pdMS_TO_TICKS(3000));
    calibratePulse();
  }

  int ring[PULSE_WINDOW];
  int head = 0;
  int count = 0;

  unsigned long beatTimes[8];
  int beatCount = 0;
  unsigned long lastBeat = 0;
  bool above = false;

  bool fingerOn = false;
  bool sentThisTouch = false;
  unsigned long fingerSince = 0;
  unsigned long lastAttempt = 0;
  unsigned long lastAnomalySent = 0;
  unsigned long lastIdleReport = 0;
  unsigned long lastPrint = 0;

  int bpm = 0;
  int prev1 = 0;
  int prev2 = 0;
  unsigned long nextSample = millis();

  for (;;) {
    unsigned long now = millis();

    if (now < nextSample) {
      vTaskDelay(pdMS_TO_TICKS(2));
      continue;
    }

    if (now > nextSample + 1000UL) {
      nextSample = now;  // we were busy uploading; resume cleanly
    }

    nextSample += PULSE_SAMPLE_MS;

    const int value = readPulseMedian();

    // 3-sample average, used only for beat detection.
    const int smooth = (value + prev1 + prev2) / 3;
    prev2 = prev1;
    prev1 = value;

    ring[head] = value;
    head = (head + 1) % PULSE_WINDOW;

    if (count < PULSE_WINDOW) {
      count++;
      continue;
    }

    int low = 0;
    int high = 0;

    const int swing = robustSwing(ring, low, high);
    const int level = windowMean(ring);
    const bool finger = gRuleMode == 1
        ? (gRuleAbove ? level > gRuleLevel : level < gRuleLevel)
        : swing > gRuleSwing;

    // ---- beats -> BPM (only meaningful with a finger on) ----------
    // A window that touches both 0 and 4095 is a contact glitch (finger
    // pressed or lifted), so beats are not counted from it.
    const bool glitch = swing > 3000;

    if (finger && !glitch) {
      const int middle = (low + high) / 2;
      const int margin = swing / 6;

      if (!above && smooth > middle + margin && now - lastBeat > 300UL) {
        above = true;
        lastBeat = now;

        if (beatCount == 8) {
          for (int i = 1; i < 8; i++) beatTimes[i - 1] = beatTimes[i];
          beatCount = 7;
        }

        beatTimes[beatCount++] = now;
      } else if (above && smooth < middle - margin) {
        above = false;
      }

      // Median of the recent beat-to-beat intervals (robust to a miss).
      if (beatCount >= 4) {
        unsigned long gaps[7];
        int n = 0;

        for (int i = 1; i < beatCount; i++) {
          const unsigned long gap = beatTimes[i] - beatTimes[i - 1];
          if (gap >= 300UL && gap <= 1500UL) gaps[n++] = gap;
        }

        if (n >= 3) {
          for (int i = 1; i < n; i++) {
            const unsigned long key = gaps[i];
            int j = i - 1;
            while (j >= 0 && gaps[j] > key) { gaps[j + 1] = gaps[j]; j--; }
            gaps[j + 1] = key;
          }

          bpm = (int)(60000UL / gaps[n / 2]);
        }
      }
    } else if (!finger) {
      beatCount = 0;
      bpm = 0;
      above = false;
    }

    // ---- finger state ---------------------------------------------
    if (finger && !fingerOn) {
      fingerOn = true;
      fingerSince = now;
      sentThisTouch = false;
      Serial.println("[PULSE] Finger detected.");
    } else if (!finger && fingerOn) {
      fingerOn = false;
      lastIdleReport = 0;
      Serial.println("[PULSE] Finger removed.");
    }

    if (PULSE_CALIBRATION_PRINT && now - lastPrint >= 1000UL) {
      lastPrint = now;

      Serial.printf(
          "[PULSE] raw=%d min=%d max=%d swing=%d level=%d finger=%s bpm=%d\n",
          value, low, high, swing, level, finger ? "yes" : "no", bpm
      );
    }

    // ---- reports (these may block for a few seconds) ----------------
    if (
        fingerOn &&
        now - fingerSince >= PULSE_STABLE_MS &&
        now - lastAttempt >= PULSE_RETRY_MS &&
        (!sentThisTouch || now - lastAnomalySent >= PULSE_REPEAT_MS) &&
        wifiReady()
    ) {
      lastAttempt = now;

      Serial.println("[PULSE] Sending encrypted ANOMALY report...");

      if (sendPulseReport(true, bpm, ring, head)) {
        sentThisTouch = true;
        lastAnomalySent = millis();
      }

      nextSample = millis();
    } else if (
        !fingerOn &&
        now - lastIdleReport >= PULSE_IDLE_REPORT_MS &&
        wifiReady()
    ) {
      lastIdleReport = now;

      sendPulseReport(false, 0, ring, head);

      nextSample = millis();
    }
  }
}

void startPulseTask() {
  analogReadResolution(12);
  analogSetPinAttenuation(PULSE_PIN, ADC_11db);

  const BaseType_t created = xTaskCreatePinnedToCore(
      pulseTask,
      "pulse",
      16384,
      nullptr,
      1,
      nullptr,
      1
  );

  Serial.println(
      created == pdPASS
          ? "Pulse sensor task started (HW-627 on GPIO 34)."
          : "ERROR: Could not start the pulse task."
  );
}
