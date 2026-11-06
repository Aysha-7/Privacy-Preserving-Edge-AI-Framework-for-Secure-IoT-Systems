from flask import Flask, request, jsonify
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import csv
import os
import threading
import math
import requests
import json
import hashlib
import io
import uuid
import cloudinary
import cloudinary.uploader

app = Flask(__name__)

# --------------------------------------------------
# HYPERLEDGER FABRIC GATEWAY CONFIGURATION
# --------------------------------------------------

FABRIC_GATEWAY_URL = os.environ.get(
    "FABRIC_GATEWAY_URL",
    "http://localhost:8080/events"
).strip()

FABRIC_GATEWAY_TOKEN = os.environ.get(
    "FABRIC_GATEWAY_TOKEN",
    ""
).strip()


# --------------------------------------------------
# FILES AND LOCKS
# --------------------------------------------------

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


# --------------------------------------------------
# ESP32 AES-256-GCM DECRYPTION CONFIGURATION
# --------------------------------------------------

key_hex = os.environ.get("AES_GCM_KEY_HEX", "").strip()

if len(key_hex) != 64:
    raise RuntimeError(
        "AES_GCM_KEY_HEX must contain a 64-character hexadecimal key."
    )

try:
    AES_KEY = bytes.fromhex(key_hex)
except ValueError as exc:
    raise RuntimeError(
        "AES_GCM_KEY_HEX is not valid hexadecimal."
    ) from exc

if len(AES_KEY) != 32:
    raise RuntimeError("AES-256 requires a 32-byte key.")

AES = AESGCM(AES_KEY)


# --------------------------------------------------
# CLOUDINARY CONFIGURATION
# --------------------------------------------------

CLOUD_NAME = os.environ.get(
    "CLOUDINARY_CLOUD_NAME", ""
).strip()

CLOUD_API_KEY = os.environ.get(
    "CLOUDINARY_API_KEY", ""
).strip()

CLOUD_API_SECRET = os.environ.get(
    "CLOUDINARY_API_SECRET", ""
).strip()

CLOUD_STORAGE_KEY_HEX = os.environ.get(
    "CLOUD_STORAGE_KEY_HEX", ""
).strip()

if not CLOUD_NAME or not CLOUD_API_KEY or not CLOUD_API_SECRET:
    raise RuntimeError("Cloudinary environment variables are missing.")

if len(CLOUD_STORAGE_KEY_HEX) != 64:
    raise RuntimeError(
        "CLOUD_STORAGE_KEY_HEX must be 64 hexadecimal characters."
    )

try:
    CLOUD_STORAGE_KEY = bytes.fromhex(CLOUD_STORAGE_KEY_HEX)
except ValueError as exc:
    raise RuntimeError(
        "CLOUD_STORAGE_KEY_HEX is invalid."
    ) from exc

if len(CLOUD_STORAGE_KEY) != 32:
    raise RuntimeError(
        "Cloud storage AES-256 requires a 32-byte key."
    )

cloudinary.config(
    cloud_name=CLOUD_NAME,
    api_key=CLOUD_API_KEY,
    api_secret=CLOUD_API_SECRET,
    secure=True,
)

# Separate key used to encrypt files stored in Cloudinary.
CLOUD_AES = AESGCM(CLOUD_STORAGE_KEY)


# --------------------------------------------------
# HASH-CHAIN FUNCTIONS
# --------------------------------------------------

def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def calculate_block_hash(block):
    contents = {
        "index": block["index"],
        "timestamp_utc": block["timestamp_utc"],
        "event": block["event"],
        "previous_hash": block["previous_hash"],
    }

    return hashlib.sha256(
        canonical_json(contents).encode("utf-8")
    ).hexdigest()


def initialize_csv():
    if not DATA_FILE.exists() or DATA_FILE.stat().st_size == 0:
        with CSV_LOCK:
            with DATA_FILE.open(
                "a", newline="", encoding="utf-8"
            ) as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=CSV_COLUMNS,
                )
                writer.writeheader()


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
                raise ValueError(
                    f"Invalid JSON at chain line {line_number}"
                ) from exc

    return blocks


def append_block(event):
    blocks = read_chain()

    previous_hash = (
        blocks[-1]["hash"] if blocks else GENESIS_HASH
    )

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


# --------------------------------------------------
# ENCRYPT EVENT AND UPLOAD TO CLOUDINARY
# --------------------------------------------------

def upload_encrypted_event_to_cloud(event):
    """
    Encrypt the verified event with a separate cloud-storage key.
    Upload only encrypted bytes and return their SHA-256 hash.
    """

    plaintext = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    # A fresh 12-byte nonce is generated for every encryption.
    nonce = os.urandom(12)

    # AES-GCM returns ciphertext with the authentication tag appended.
    ciphertext_with_tag = CLOUD_AES.encrypt(
        nonce,
        plaintext,
        None,
    )

    encrypted_file = {
        "format": "AES-256-GCM",
        "nonce": base64.b64encode(
            nonce
        ).decode("ascii"),
        "ciphertext_and_tag": base64.b64encode(
            ciphertext_with_tag
        ).decode("ascii"),
    }

    file_bytes = json.dumps(
        encrypted_file,
        separators=(",", ":"),
    ).encode("utf-8")

    # Hash the exact bytes uploaded to Cloudinary.
    encrypted_file_hash = hashlib.sha256(
        file_bytes
    ).hexdigest()

    public_id = f"event_{uuid.uuid4().hex}"

    result = cloudinary.uploader.upload(
        io.BytesIO(file_bytes),
        resource_type="raw",
        folder="encrypted_iot_events",
        public_id=public_id,
        overwrite=False,
    )

    return {
        "public_id": result.get("public_id"),
        "resource_type": result.get("resource_type"),
        "encrypted_file_hash": encrypted_file_hash,
    }


# --------------------------------------------------
# SUBMIT ENCRYPTED EVENT METADATA TO HYPERLEDGER FABRIC
# --------------------------------------------------

def record_event_on_fabric(
    event_id,
    timestamp,
    encrypted_file_hash,
    cloud_reference,
):
    """
    Submit only metadata to Hyperledger Fabric.
    Sensor readings and encryption keys are never sent to the ledger.
    """

    if not FABRIC_GATEWAY_TOKEN:
        raise RuntimeError(
            "FABRIC_GATEWAY_TOKEN is not configured."
        )

    if not encrypted_file_hash or len(encrypted_file_hash) != 64:
        raise ValueError(
            "Invalid encrypted file SHA-256 hash."
        )

    payload = {
        "eventId": event_id,
        "timestamp": timestamp,
        "encryptedFileHash": encrypted_file_hash,
        "cloudReference": cloud_reference,
    }

    response = requests.post(
        FABRIC_GATEWAY_URL,
        json=payload,
        headers={
            "Authorization": f"Bearer {FABRIC_GATEWAY_TOKEN}",
            "Content-Type": "application/json",
        },
        timeout=15,
    )

    response.raise_for_status()

    return response.json()


# --------------------------------------------------
# INITIALIZE LOCAL STORAGE
# --------------------------------------------------

initialize_csv()


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

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


# --------------------------------------------------
# RECEIVE, VERIFY, STORE AND UPLOAD SENSOR EVENTS
# --------------------------------------------------

@app.post("/api/sensor")
def receive_sensor_data():
    envelope = request.get_json(silent=True)

    if not isinstance(envelope, dict):
        return jsonify({
            "error": "Expected a JSON object"
        }), 400

    required = [
        "device_id",
        "nonce",
        "ciphertext",
        "tag",
    ]

    missing = [
        field for field in required
        if field not in envelope
    ]

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
        return jsonify({
            "error": "Invalid device_id"
        }), 400

    # --------------------------------------------------
    # DECRYPT AND AUTHENTICATE THE ESP32 PAYLOAD
    # --------------------------------------------------

    try:
        nonce = base64.b64decode(
            envelope["nonce"],
            validate=True,
        )

        ciphertext = base64.b64decode(
            envelope["ciphertext"],
            validate=True,
        )

        tag = base64.b64decode(
            envelope["tag"],
            validate=True,
        )

        if len(nonce) != 12:
            return jsonify({
                "error": "Nonce must be 12 bytes"
            }), 400

        if len(tag) != 16:
            return jsonify({
                "error": "Authentication tag must be 16 bytes"
            }), 400

        plaintext = AES.decrypt(
            nonce,
            ciphertext + tag,
            device_id.encode("utf-8"),
        )

        data = json.loads(
            plaintext.decode("utf-8")
        )

    except Exception:
        return jsonify({
            "error": (
                "Encrypted event verification or decryption failed"
            )
        }), 400

    # --------------------------------------------------
    # VALIDATE DECRYPTED PAYLOAD
    # --------------------------------------------------

    if not isinstance(data, dict):
        return jsonify({
            "error": "Decrypted payload must be a JSON object"
        }), 400

    if data.get("device_id") != device_id:
        return jsonify({
            "error": "Device ID mismatch"
        }), 400

    if data.get("prediction") != "HIGH_HUMIDITY":
        return jsonify({
            "error": (
                "Only HIGH_HUMIDITY events are accepted"
            )
        }), 400

    try:
        temperature = float(data["temperature"])
        humidity = float(data["humidity"])

        if (
            not math.isfinite(temperature)
            or not -40 <= temperature <= 80
        ):
            raise ValueError(
                "Temperature is outside the accepted range"
            )

        if (
            not math.isfinite(humidity)
            or not 0 <= humidity <= 100
        ):
            raise ValueError(
                "Humidity is outside the accepted range"
            )

    except (KeyError, TypeError, ValueError) as exc:
        return jsonify({
            "error": str(exc)
        }), 400

    # --------------------------------------------------
    # CREATE VERIFIED EVENT RECORD
    # --------------------------------------------------

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    record = {
        "timestamp_utc": timestamp,
        "device_id": device_id,
        "temperature_c": temperature,
        "humidity_percent": humidity,
        "prediction": "HIGH_HUMIDITY",
    }

    # --------------------------------------------------
    # STORE LOCALLY AND APPEND TO THE HASH CHAIN
    # --------------------------------------------------

    with CSV_LOCK:
        try:
            with DATA_FILE.open(
                "a",
                newline="",
                encoding="utf-8",
            ) as f:
                csv.DictWriter(
                    f,
                    fieldnames=CSV_COLUMNS,
                ).writerow(record)

            block = append_block(record)

        except Exception:
            app.logger.exception(
                "Failed to store event or append hash-chain block"
            )

            return jsonify({
                "error": (
                    "Local storage or hash-chain operation failed. "
                    "Check the server files before retrying."
                )
            }), 500

    print(
        f"[{timestamp}] Verified encrypted anomaly from "
        f"{device_id}; hash-chain block {block['index']} added."
    )

    # --------------------------------------------------
    # UPLOAD ENCRYPTED EVENT TO CLOUDINARY
    # THEN RECORD ITS METADATA ON FABRIC
    # --------------------------------------------------

    cloud_status = "failed"
    cloud_public_id = None
    fabric_status = "skipped"
    fabric_result = None
    fabric_event_id = None

    try:
        cloud_result = upload_encrypted_event_to_cloud(record)

        cloud_public_id = cloud_result.get("public_id")
        encrypted_file_hash = cloud_result.get(
            "encrypted_file_hash"
        )

        if not cloud_public_id or not encrypted_file_hash:
            raise RuntimeError(
                "Cloud upload result is missing public_id or file hash."
            )

        cloud_status = "uploaded"

        print(
            "Encrypted event uploaded to Cloudinary: "
            f"{cloud_public_id}"
        )

        # Cloudinary public_id may contain a folder prefix.
        # The Fabric event ID must not contain a slash.
        fabric_event_id = cloud_public_id.rsplit("/", 1)[-1]

        try:
            fabric_result = record_event_on_fabric(
                event_id=fabric_event_id,
                timestamp=timestamp,
                encrypted_file_hash=encrypted_file_hash,
                cloud_reference=cloud_public_id,
            )

            fabric_status = "recorded"

            print(
                "Event metadata recorded on Fabric: "
                f"{fabric_event_id}"
            )

        except Exception:
            fabric_status = "failed"

            app.logger.exception(
                "Fabric recording failed. The event remains stored "
                "locally and in Cloudinary."
            )

    except Exception:
        cloud_status = "failed"
        fabric_status = "skipped"

        app.logger.exception(
            "Cloudinary upload failed. The event remains stored locally."
        )

    # --------------------------------------------------
    # RETURN RESULT
    # --------------------------------------------------

    return jsonify({
        "status": "success",
        "message": "Encrypted anomaly verified and saved locally",
        "device_id": device_id,
        "prediction": "HIGH_HUMIDITY",
        "timestamp_utc": timestamp,
        "block_index": block["index"],
        "block_hash": block["hash"],
        "cloud_storage_status": cloud_status,
        "cloud_public_id": cloud_public_id,
        "fabric_status": fabric_status,
        "fabric_event_id": fabric_event_id,
        "fabric_event": fabric_result,
    }), 201


# --------------------------------------------------
# GET LATEST LOCAL SENSOR RECORDS
# --------------------------------------------------

@app.get("/api/latest")
def latest_records():
    count = request.args.get(
        "count",
        default=20,
        type=int,
    )

    count = max(1, min(count or 20, 100))

    with CSV_LOCK:
        with DATA_FILE.open(
            "r",
            newline="",
            encoding="utf-8",
        ) as f:
            records = list(csv.DictReader(f))

    return jsonify({
        "count": min(count, len(records)),
        "records": records[-count:][::-1],
    })


# --------------------------------------------------
# VERIFY THE LOCAL HASH CHAIN
# --------------------------------------------------

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
                    "error": (
                        "Block hash mismatch; event may have been modified"
                    ),
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
        app.logger.exception(
            "Hash-chain verification failed"
        )

        return jsonify({
            "valid": False,
            "error": "Unable to read or verify hash chain",
        }), 500


# --------------------------------------------------
# START SERVER
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )