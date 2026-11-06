
from flask import Flask, request, jsonify
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import csv
import os
import threading
import math
import json
import hashlib

app = Flask(__name__)

DATA_FILE = Path(__file__).resolve().parent / "sensor_data.csv"
CHAIN_FILE = Path(__file__).resolve().parent / "blockchain.jsonl"
CSV_LOCK = threading.Lock()

CSV_COLUMNS = [
    "timestamp_utc",
    "device_id",
    "temperature_c",
    "humidity_percent",
    "prediction",
]

GENESIS_HASH = "0" * 64

key_hex = os.environ.get("AES_GCM_KEY_HEX", "").strip()
if len(key_hex) != 64:
    raise RuntimeError("AES_GCM_KEY_HEX must contain a 64-character hexadecimal key.")

try:
    AES_KEY = bytes.fromhex(key_hex)
except ValueError as exc:
    raise RuntimeError("AES_GCM_KEY_HEX is not valid hexadecimal.") from exc

if len(AES_KEY) != 32:
    raise RuntimeError("AES-256 requires a 32-byte key.")

AES = AESGCM(AES_KEY)


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def calculate_block_hash(block):
    contents = {
        "index": block["index"],
        "timestamp_utc": block["timestamp_utc"],
        "event": block["event"],
        "previous_hash": block["previous_hash"],
    }
    return hashlib.sha256(canonical_json(contents).encode("utf-8")).hexdigest()


def initialize_csv():
    if not DATA_FILE.exists() or DATA_FILE.stat().st_size == 0:
        with CSV_LOCK:
            with DATA_FILE.open("a", newline="", encoding="utf-8") as f:
                csv.DictWriter(f, fieldnames=CSV_COLUMNS).writeheader()


def read_chain():
    if not CHAIN_FILE.exists():
        return []

    blocks = []
    with CHAIN_FILE.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                blocks.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at chain line {line_number}") from exc
    return blocks


def append_block(event):
    blocks = read_chain()
    previous_hash = blocks[-1]["hash"] if blocks else GENESIS_HASH

    block = {
        "index": len(blocks),
        "timestamp_utc": event["timestamp_utc"],
        "event": event,
        "previous_hash": previous_hash,
    }
    block["hash"] = calculate_block_hash(block)

    with CHAIN_FILE.open("a", encoding="utf-8") as f:
        f.write(canonical_json(block) + "\n")

    return block


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
      <p><a href="/api/latest">Latest records</a></p>
      <p><a href="/api/verify-chain">Verify hash chain</a></p>
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
        return jsonify({"error": "Encrypted envelope is incomplete", "missing": missing}), 400

    device_id = envelope["device_id"]
    if not isinstance(device_id, str) or not device_id or len(device_id) > 64:
        return jsonify({"error": "Invalid device_id"}), 400

    try:
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        tag = base64.b64decode(envelope["tag"], validate=True)

        if len(nonce) != 12:
            return jsonify({"error": "Nonce must be 12 bytes"}), 400
        if len(tag) != 16:
            return jsonify({"error": "Authentication tag must be 16 bytes"}), 400

        plaintext = AES.decrypt(nonce, ciphertext + tag, device_id.encode("utf-8"))
        data = json.loads(plaintext.decode("utf-8"))

    except Exception:
        return jsonify({"error": "Encrypted event verification or decryption failed"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "Decrypted payload must be a JSON object"}), 400
    if data.get("device_id") != device_id:
        return jsonify({"error": "Device ID mismatch"}), 400
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
        # Record the verified event in the existing CSV.
        with DATA_FILE.open("a", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=CSV_COLUMNS).writerow(record)

        # Add the same event to the hash chain.
        try:
            block = append_block(record)
        except Exception:
            app.logger.exception("Failed to append event to hash chain")
            return jsonify({
                "error": "Event was saved to CSV, but hash-chain append failed"
            }), 500

    print(f"[{timestamp}] Verified encrypted anomaly from {device_id}; hash-chain block {block['index']} added.")

    return jsonify({
        "status": "success",
        "message": "Encrypted anomaly verified and saved",
        "device_id": device_id,
        "prediction": "HIGH_HUMIDITY",
        "timestamp_utc": timestamp,
        "block_index": block["index"],
        "block_hash": block["hash"],
    }), 201


@app.get("/api/latest")
def latest_records():
    count = request.args.get("count", default=20, type=int)
    count = max(1, min(count or 20, 100))

    with CSV_LOCK:
        with DATA_FILE.open("r", newline="", encoding="utf-8") as f:
            records = list(csv.DictReader(f))

    return jsonify({"count": min(count, len(records)), "records": records[-count:][::-1]})


@app.get("/api/verify-chain")
def verify_chain():
    try:
        with CSV_LOCK:
            blocks = read_chain()

        previous_hash = GENESIS_HASH
        for expected_index, block in enumerate(blocks):
            if block.get("index") != expected_index:
                return jsonify({
                    "valid": False,
                    "error": "Block index mismatch",
                    "block_index": expected_index,
                }), 200

            if block.get("previous_hash") != previous_hash:
                return jsonify({
                    "valid": False,
                    "error": "Previous-hash link mismatch",
                    "block_index": expected_index,
                }), 200

            if block.get("hash") != calculate_block_hash(block):
                return jsonify({
                    "valid": False,
                    "error": "Block hash mismatch; event may have been modified",
                    "block_index": expected_index,
                }), 200

            previous_hash = block["hash"]

        return jsonify({
            "valid": True,
            "message": "Hash chain verified successfully",
            "block_count": len(blocks),
            "latest_hash": previous_hash,
        })

    except Exception:
        app.logger.exception("Hash-chain verification failed")
        return jsonify({"valid": False, "error": "Unable to read or verify hash chain"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

