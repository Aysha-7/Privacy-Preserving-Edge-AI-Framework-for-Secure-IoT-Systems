import os
import json
import base64
import secrets
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_URL = "http://127.0.0.1:5000"
DEVICE_ID = "ESP32-CAM"

key_hex = os.environ.get("CAMERA_AES_GCM_KEY_HEX", "")
if len(key_hex) != 64:
    raise SystemExit("ERROR: Camera AES key is missing or invalid.")

key = bytes.fromhex(key_hex)

event = {
    "source": "ESP32-CAM",
    "event_type": "INTRUSION",
    "detection": "TINYML_PERSON_CLASSIFIER",
    "status": "ANOMALY",
    "security_mode": "ARMED",
    "context": "SOFTWARE_PIPELINE_TEST",
    "person_confidence": 0.95,
    "motion_score": 25.0,
}

nonce = secrets.token_bytes(12)
encrypted = AESGCM(key).encrypt(
    nonce,
    json.dumps(event, separators=(",", ":")).encode("utf-8"),
    DEVICE_ID.encode("utf-8"),
)

envelope = {
    "device_id": DEVICE_ID,
    "nonce": base64.b64encode(nonce).decode("ascii"),
    "ciphertext": base64.b64encode(encrypted[:-16]).decode("ascii"),
    "tag": base64.b64encode(encrypted[-16:]).decode("ascii"),
}

session = requests.Session()

# Reuse an authenticated session cookie if one is available.
cookie = os.environ.get("FLASK_SESSION_COOKIE")
if cookie:
    session.cookies.set("session", cookie)

print("Submitting one encrypted software test event...")
print("If authentication is required, log in to the dashboard first.")

response = session.post(
    f"{BASE_URL}/api/camera-event",
    json=envelope,
    timeout=60,
)

print("HTTP status:", response.status_code)
try:
    result = response.json()
    print(json.dumps(result, indent=2))
except ValueError:
    print(response.text[:1000])