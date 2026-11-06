import os
import io
import json
import uuid
import base64
import hashlib
import secrets
from pathlib import Path

import requests
import cloudinary
import cloudinary.uploader
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
IMAGE_PATH = BASE_DIR / "test_anomaly.jpg"

CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME", "").strip()
CLOUD_API_KEY = os.environ.get("CLOUDINARY_API_KEY", "").strip()
CLOUD_API_SECRET = os.environ.get("CLOUDINARY_API_SECRET", "").strip()
STORAGE_KEY_HEX = os.environ.get("CLOUD_STORAGE_KEY_HEX", "").strip()

FABRIC_URL = os.environ.get(
    "FABRIC_GATEWAY_URL",
    "http://localhost:8080/events",
).strip()

FABRIC_TOKEN = os.environ.get("FABRIC_GATEWAY_TOKEN", "").strip()

if not IMAGE_PATH.is_file():
    raise SystemExit("ERROR: test_anomaly.jpg was not found.")

if not all([CLOUD_NAME, CLOUD_API_KEY, CLOUD_API_SECRET, FABRIC_TOKEN]):
    raise SystemExit("ERROR: Cloudinary or Fabric configuration is missing.")

if len(STORAGE_KEY_HEX) != 64:
    raise SystemExit("ERROR: CLOUD_STORAGE_KEY_HEX must be 64 hex characters.")

try:
    storage_key = bytes.fromhex(STORAGE_KEY_HEX)
except ValueError:
    raise SystemExit("ERROR: CLOUD_STORAGE_KEY_HEX is invalid.")

if len(storage_key) != 32:
    raise SystemExit("ERROR: Storage key must be 32 bytes.")


# --------------------------------------------------
# ENCRYPT THE IMAGE
# --------------------------------------------------

image_bytes = IMAGE_PATH.read_bytes()

if not image_bytes.startswith(b"\xff\xd8\xff"):
    raise SystemExit("ERROR: The test file is not a JPEG image.")

nonce = secrets.token_bytes(12)

ciphertext_and_tag = AESGCM(storage_key).encrypt(
    nonce,
    image_bytes,
    None,
)

envelope = {
    "format": "AES-256-GCM-IMAGE",
    "content_type": "image/jpeg",
    "nonce": base64.b64encode(nonce).decode("ascii"),
    "ciphertext_and_tag": base64.b64encode(
        ciphertext_and_tag
    ).decode("ascii"),
}

encrypted_bytes = json.dumps(
    envelope,
    separators=(",", ":"),
).encode("utf-8")

encrypted_hash = hashlib.sha256(encrypted_bytes).hexdigest()
event_id = f"image_{uuid.uuid4().hex}"
timestamp = __import__("datetime").datetime.now(
    __import__("datetime").timezone.utc
).isoformat()

print("Image encryption: PASS")
print("Original image bytes:", len(image_bytes))
print("Encrypted envelope SHA-256:", encrypted_hash)


# --------------------------------------------------
# UPLOAD ENCRYPTED IMAGE TO CLOUDINARY
# --------------------------------------------------

cloudinary.config(
    cloud_name=CLOUD_NAME,
    api_key=CLOUD_API_KEY,
    api_secret=CLOUD_API_SECRET,
    secure=True,
)

result = cloudinary.uploader.upload(
    io.BytesIO(encrypted_bytes),
    resource_type="raw",
    folder="encrypted_iot_events",
    public_id=event_id,
    overwrite=False,
)

cloud_reference = result.get("public_id")

if not cloud_reference:
    raise SystemExit("ERROR: Cloudinary returned no public ID.")

print("Cloudinary upload: PASS")
print("Reference:", cloud_reference)


# --------------------------------------------------
# RECORD IMAGE HASH AND REFERENCE ON FABRIC
# --------------------------------------------------

payload = {
    "eventId": event_id,
    "timestamp": timestamp,
    "encryptedFileHash": encrypted_hash,
    "cloudReference": cloud_reference,
}

try:
    response = requests.post(
        FABRIC_URL,
        json=payload,
        headers={
            "Authorization": f"Bearer {FABRIC_TOKEN}",
            "Content-Type": "application/json",
        },
        timeout=20,
    )
    response.raise_for_status()

except Exception as exc:
    print("ERROR: Fabric recording failed:", type(exc).__name__)
    print(
        "The encrypted image may already exist in Cloudinary. "
        "Do not assume it was rolled back."
    )
    raise SystemExit(1)


# Save non-secret lookup information for the recovery endpoint.
# This file contains no encryption key or plaintext image.
metadata_path = BASE_DIR / "image_events.jsonl"

metadata = {
    "event_id": event_id,
    "timestamp_utc": timestamp,
    "cloud_public_id": cloud_reference,
    "encrypted_file_hash": encrypted_hash,
    "content_type": "image/jpeg",
    "fabric_status": "recorded",
}

with metadata_path.open("a", encoding="utf-8") as file:
    file.write(json.dumps(metadata, separators=(",", ":")) + "\n")

print("Fabric recording: PASS")
print("Image event ID:", event_id)
print("Lookup metadata saved to image_events.jsonl")
print("Encrypted image workflow completed.")