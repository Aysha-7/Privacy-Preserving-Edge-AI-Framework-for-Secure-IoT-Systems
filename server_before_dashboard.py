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
from flask import (
    render_template_string,
    redirect,
    url_for,
    session,
    abort,
)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
from functools import wraps

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", ""),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Enable True when served over HTTPS
    PERMANENT_SESSION_LIFETIME=1800,
)

if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY is not configured.")

DASHBOARD_PASSWORD_HASH = os.environ.get(
    "DASHBOARD_PASSWORD_HASH", ""
).strip()

if not DASHBOARD_PASSWORD_HASH:
    raise RuntimeError("DASHBOARD_PASSWORD_HASH is not configured.")

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
)

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
# DASHBOARD AUTHENTICATION
# --------------------------------------------------

LOGIN_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IoT Dashboard Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f1f5f9;
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
        }
        .card {
            background: white;
            padding: 32px;
            border-radius: 12px;
            width: min(360px, calc(100% - 64px));
            box-shadow: 0 8px 28px #0001;
        }
        h1 { font-size: 24px; }
        label { display: block; margin-top: 18px; }
        input {
            box-sizing: border-box;
            width: 100%;
            padding: 12px;
            margin-top: 8px;
        }
        button {
            width: 100%;
            padding: 12px;
            margin-top: 20px;
            background: #0f766e;
            color: white;
            border: 0;
            border-radius: 6px;
            cursor: pointer;
        }
        .error { color: #b91c1c; }
    </style>
</head>
<body>
    <main class="card">
        <h1>Secure IoT Dashboard</h1>
        <p>Sign in to view protected sensor events.</p>

        {% if error %}
        <p class="error" role="alert">{{ error }}</p>
        {% endif %}

        <form method="post" action="{{ url_for('login') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <label for="password">Dashboard password</label>
            <input
                id="password"
                name="password"
                type="password"
                autocomplete="current-password"
                required
                minlength="12"
            >

            <button type="submit">Sign in</button>
        </form>
    </main>
</body>
</html>
"""


def dashboard_login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if not session.get("dashboard_authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401

            return redirect(url_for("login"))

        return view_function(*args, **kwargs)

    return wrapped_view


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if session.get("dashboard_authenticated"):
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        password = request.form.get("password", "")

        if check_password_hash(DASHBOARD_PASSWORD_HASH, password):
            session.clear()
            session["dashboard_authenticated"] = True
            session.permanent = True

            return redirect(url_for("home"))

        error = "Invalid password. Please try again."

    return render_template_string(LOGIN_PAGE, error=error)


@app.post("/logout")
@dashboard_login_required
def logout():
    session.clear()
    return redirect(url_for("login"))
# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.get("/")
@dashboard_login_required
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
# RECEIVE ENCRYPTED ESP32-CAM EVENTS
# --------------------------------------------------

CAMERA_AES_KEY_HEX = os.environ.get(
    "CAMERA_AES_GCM_KEY_HEX", ""
).strip()

if len(CAMERA_AES_KEY_HEX) != 64:
    raise RuntimeError(
        "CAMERA_AES_GCM_KEY_HEX must contain a 64-character hex key."
    )

try:
    CAMERA_AES_KEY = bytes.fromhex(CAMERA_AES_KEY_HEX)
except ValueError as exc:
    raise RuntimeError(
        "CAMERA_AES_GCM_KEY_HEX must be hexadecimal."
    ) from exc

if len(CAMERA_AES_KEY) != 32:
    raise RuntimeError("Camera AES key must be 32 bytes.")

CAMERA_AES = AESGCM(CAMERA_AES_KEY)

CAMERA_EVENTS_FILE = (
    Path(__file__).resolve().parent / "camera_events.jsonl"
)

CAMERA_LOCK = threading.Lock()


@app.post("/api/camera-event")
@csrf.exempt
@limiter.limit("30 per minute")
def receive_camera_event():
    envelope = request.get_json(silent=True)

    if not isinstance(envelope, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    required = ["device_id", "nonce", "ciphertext", "tag"]

    if any(field not in envelope for field in required):
        return jsonify({
            "error": "Incomplete encrypted camera event",
            "required_fields": required,
        }), 400

    device_id = envelope.get("device_id")

    if device_id != "ESP32-CAM":
        return jsonify({"error": "Invalid camera device ID"}), 400

    try:
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(
            envelope["ciphertext"], validate=True
        )
        tag = base64.b64decode(envelope["tag"], validate=True)

        if len(nonce) != 12 or len(tag) != 16:
            return jsonify({
                "error": "Invalid nonce or authentication tag length"
            }), 400

        plaintext = CAMERA_AES.decrypt(
            nonce,
            ciphertext + tag,
            device_id.encode("utf-8"),
        )

        event = json.loads(plaintext.decode("utf-8"))

    except Exception:
        return jsonify({
            "error": "Camera event authentication or decryption failed"
        }), 400

    if not isinstance(event, dict):
        return jsonify({"error": "Event must be a JSON object"}), 400

    if (
        event.get("source") != "ESP32-CAM"
        or event.get("event_type") != "INTRUSION"
        or event.get("detection") != "TINYML_PERSON_CLASSIFIER"
        or event.get("status") != "ANOMALY"
        or event.get("security_mode") != "ARMED"
    ):
        return jsonify({"error": "Invalid camera event fields"}), 400

    try:
        confidence = float(event["person_confidence"])
        motion_score = float(event["motion_score"])

        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError()

        if not math.isfinite(motion_score) or not 0 <= motion_score <= 100:
            raise ValueError()

    except (KeyError, TypeError, ValueError):
        return jsonify({
            "error": "Invalid confidence or motion score"
        }), 400

    timestamp = datetime.now(timezone.utc).isoformat()

    record = {
        "event_id": f"cam_{uuid.uuid4().hex}",
        "timestamp_utc": timestamp,
        "device_id": device_id,
        "event_type": "INTRUSION",
        "detection": "TINYML_PERSON_CLASSIFIER",
        "security_mode": "ARMED",
        "context": str(event.get("context", "UNKNOWN"))[:80],
        "person_confidence": confidence,
        "motion_score": motion_score,
        "status": "ANOMALY",
    }

    with CAMERA_LOCK:
        try:
            with CAMERA_EVENTS_FILE.open(
                "a", encoding="utf-8"
            ) as f:
                f.write(canonical_json(record) + "\n")
        except OSError:
            app.logger.exception("Failed to save camera event")
            return jsonify({
                "error": "Could not save camera event"
            }), 500

    cloud_status = "failed"
    fabric_status = "skipped"
    cloud_public_id = None
    fabric_event_id = None

    try:
        cloud_result = upload_encrypted_event_to_cloud(record)

        cloud_public_id = cloud_result.get("public_id")
        encrypted_hash = cloud_result.get("encrypted_file_hash")

        if not cloud_public_id or not encrypted_hash:
            raise RuntimeError("Cloud upload returned incomplete metadata")

        cloud_status = "uploaded"
        fabric_event_id = cloud_public_id.rsplit("/", 1)[-1]

        try:
            record_event_on_fabric(
                event_id=fabric_event_id,
                timestamp=timestamp,
                encrypted_file_hash=encrypted_hash,
                cloud_reference=cloud_public_id,
            )
            fabric_status = "recorded"

        except Exception:
            fabric_status = "failed"
            app.logger.exception("Failed to record camera metadata on Fabric")

    except Exception:
        app.logger.exception("Failed to upload camera event to Cloudinary")

    return jsonify({
        "status": "success",
        "message": "Encrypted camera event authenticated and stored locally",
        "event_id": record["event_id"],
        "timestamp_utc": timestamp,
        "cloud_storage_status": cloud_status,
        "cloud_public_id": cloud_public_id,
        "fabric_status": fabric_status,
        "fabric_event_id": fabric_event_id,
    }), 201
# --------------------------------------------------
# GET LATEST LOCAL SENSOR RECORDS
# --------------------------------------------------

@app.get("/api/latest")
@dashboard_login_required
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
@dashboard_login_required
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