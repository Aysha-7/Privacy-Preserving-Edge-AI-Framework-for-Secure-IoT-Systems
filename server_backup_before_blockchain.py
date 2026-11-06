
from flask import Flask, request, jsonify
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import csv
import os
import threading
import math

app = Flask(__name__)

DATA_FILE = Path(__file__).resolve().parent / "sensor_data.csv"
CSV_LOCK = threading.Lock()

CSV_COLUMNS = [
    "timestamp_utc",
    "device_id",
    "temperature_c",
    "humidity_percent",
    "prediction",
]

# Set AES_GCM_KEY_HEX in the environment before starting the server.
key_hex = os.environ.get("AES_GCM_KEY_HEX", "").strip()

if len(key_hex) != 64:
    raise RuntimeError(
        "AES_GCM_KEY_HEX must contain a 64-character hexadecimal key."
    )

try:
    AES_KEY = bytes.fromhex(key_hex)
except ValueError as exc:
    raise RuntimeError("AES_GCM_KEY_HEX is not valid hexadecimal.") from exc

if len(AES_KEY) != 32:
    raise RuntimeError("AES-256 requires a 32-byte key.")

AES = AESGCM(AES_KEY)


def initialize_csv():
    if not DATA_FILE.exists() or DATA_FILE.stat().st_size == 0:
        with CSV_LOCK:
            with DATA_FILE.open("a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writeheader()


initialize_csv()


@app.get("/")
def home():
    return """
    <!doctype html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>TinyML Encrypted IoT Monitor</title>
    </head>
    <body style="font-family:Arial;max-width:700px;margin:40px auto;padding:0 15px">
        <h1>TinyML Encrypted IoT Monitor</h1>
        <p>Flask server is running.</p>
        <p>POST encrypted anomaly events to <code>/api/sensor</code>.</p>
        <p>View saved records at <a href="/api/latest">/api/latest</a>.</p>
    </body>
    </html>
    """


@app.post("/api/sensor")
def receive_sensor_data():
    envelope = request.get_json(silent=True)

    if not isinstance(envelope, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    required = ["device_id", "nonce", "ciphertext", "tag"]
    missing = [field for field in required if field not in envelope]

    if missing:
        return jsonify({
            "error": "Encrypted envelope is incomplete",
            "missing": missing,
        }), 400

    device_id = envelope["device_id"]

    if (
        not isinstance(device_id, str)
        or not device_id
        or len(device_id) > 64
    ):
        return jsonify({"error": "Invalid device_id"}), 400

    try:
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(
            envelope["ciphertext"], validate=True
        )
        tag = base64.b64decode(envelope["tag"], validate=True)

        if len(nonce) != 12:
            return jsonify({"error": "Nonce must be 12 bytes"}), 400

        if len(tag) != 16:
            return jsonify({"error": "Authentication tag must be 16 bytes"}), 400

        # device_id is authenticated as additional authenticated data.
        plaintext = AES.decrypt(
            nonce,
            ciphertext + tag,
            device_id.encode("utf-8"),
        )

        data = __import__("json").loads(plaintext.decode("utf-8"))

    except Exception:
        # Do not disclose whether the key, tag, nonce, or payload was wrong.
        return jsonify({
            "error": "Encrypted event verification or decryption failed"
        }), 400

    if not isinstance(data, dict):
        return jsonify({"error": "Decrypted payload must be a JSON object"}), 400

    # The identity in the outer envelope must match the encrypted payload.
    if data.get("device_id") != device_id:
        return jsonify({"error": "Device ID mismatch"}), 400

    # Reject normal readings even if someone bypasses the ESP32 filter.
    if data.get("prediction") != "HIGH_HUMIDITY":
        return jsonify({"error": "Only HIGH_HUMIDITY events are accepted"}), 400

    try:
        temperature = float(data["temperature"])
        humidity = float(data["humidity"])

        if not math.isfinite(temperature) or not -40 <= temperature <= 80:
            raise ValueError("Temperature is outside the accepted range")

        if not math.isfinite(humidity) or not 0 <= humidity <= 100:
            raise ValueError("Humidity is outside the accepted range")

    except (KeyError, TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    timestamp = datetime.now(timezone.utc).isoformat()

    record = {
        "timestamp_utc": timestamp,
        "device_id": device_id,
        "temperature_c": temperature,
        "humidity_percent": humidity,
        "prediction": "HIGH_HUMIDITY",
    }

    with CSV_LOCK:
        with DATA_FILE.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writerow(record)

    print(
        f"[{timestamp}] Verified encrypted anomaly from {device_id}; "
        "payload authenticated and decrypted."
    )

    # Return confirmation without returning the decrypted sensor values.
    return jsonify({
        "status": "success",
        "message": "Encrypted anomaly verified and saved",
        "device_id": device_id,
        "prediction": "HIGH_HUMIDITY",
        "timestamp_utc": timestamp,
    }), 201


@app.get("/api/latest")
def latest_records():
    count = request.args.get("count", default=20, type=int)
    count = max(1, min(count or 20, 100))

    with CSV_LOCK:
        with DATA_FILE.open("r", newline="", encoding="utf-8") as f:
            records = list(csv.DictReader(f))

    return jsonify({
        "count": min(count, len(records)),
        "records": records[-count:][::-1],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
