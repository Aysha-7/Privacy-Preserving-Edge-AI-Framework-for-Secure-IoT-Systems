import os
import json
import base64
import hashlib

import requests
import cloudinary
import cloudinary.api

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# --------------------------------------------------
# CONFIGURATION: Read secrets from environment only
# --------------------------------------------------

FABRIC_TOKEN = os.environ.get("FABRIC_GATEWAY_TOKEN", "")
CLOUD_KEY_HEX = os.environ.get("CLOUD_STORAGE_KEY_HEX", "")

CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME", "")
CLOUD_API_KEY = os.environ.get("CLOUDINARY_API_KEY", "")
CLOUD_API_SECRET = os.environ.get("CLOUDINARY_API_SECRET", "")

GATEWAY_URL = os.environ.get(
    "FABRIC_GATEWAY_URL",
    "http://localhost:8080/events"
)

EVENT_ID = "event_cca7b2ded2fe4d61876ba8502151833a"


def require_environment():
    required = {
        "FABRIC_GATEWAY_TOKEN": FABRIC_TOKEN,
        "CLOUD_STORAGE_KEY_HEX": CLOUD_KEY_HEX,
        "CLOUDINARY_CLOUD_NAME": CLOUD_NAME,
        "CLOUDINARY_API_KEY": CLOUD_API_KEY,
        "CLOUDINARY_API_SECRET": CLOUD_API_SECRET,
    }

    missing = [name for name, value in required.items() if not value]

    if missing:
        raise RuntimeError(
            "Missing environment variables: " + ", ".join(missing)
        )

    try:
        key = bytes.fromhex(CLOUD_KEY_HEX)
    except ValueError as exc:
        raise RuntimeError(
            "Cloud encryption key is not valid hexadecimal."
        ) from exc

    if len(key) != 32:
        raise RuntimeError(
            "Cloud encryption key must decode to 32 bytes."
        )

    return key


def main():
    key = require_environment()

    cloudinary.config(
        cloud_name=CLOUD_NAME,
        api_key=CLOUD_API_KEY,
        api_secret=CLOUD_API_SECRET,
        secure=True,
    )

    print("=== End-to-End Cloud Event Verification ===")

    # 1. Retrieve metadata from Fabric.
    print("\n[1/5] Querying Fabric event metadata...")

    response = requests.get(
        f"{GATEWAY_URL.rstrip('/')}/{EVENT_ID}",
        headers={"Authorization": f"Bearer {FABRIC_TOKEN}"},
        timeout=20,
    )
    response.raise_for_status()

    result = response.json()

    if result.get("status") != "found" or not isinstance(
        result.get("event"), dict
    ):
        raise RuntimeError("Fabric did not return a valid event record.")

    event = result["event"]

    if event.get("eventId") != EVENT_ID:
        raise RuntimeError("Fabric returned a different event ID.")

    expected_hash = event.get("encryptedFileHash", "")
    cloud_reference = event.get("cloudReference", "")

    if (
        len(expected_hash) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in expected_hash)
    ):
        raise RuntimeError("Fabric returned an invalid SHA-256 hash.")

    if not cloud_reference:
        raise RuntimeError("Fabric record has no Cloudinary reference.")

    print("Fabric record: PASS")
    print("Event ID matches: PASS")

    # 2. Retrieve the raw asset's authenticated Cloudinary URL.
    print("\n[2/5] Looking up the Cloudinary asset...")

    asset = cloudinary.api.resource(
        cloud_reference,
        resource_type="raw",
    )

    secure_url = asset.get("secure_url")

    if not secure_url:
        raise RuntimeError("Cloudinary did not return a secure download URL.")

    download = requests.get(secure_url, timeout=30)
    download.raise_for_status()
    encrypted_bytes = download.content

    if not encrypted_bytes:
        raise RuntimeError("Cloudinary returned an empty file.")

    print("Cloudinary download: PASS")
    print("Downloaded bytes:", len(encrypted_bytes))

    # 3. Verify the exact downloaded bytes before decrypting.
    print("\n[3/5] Comparing SHA-256 with Fabric...")

    actual_hash = hashlib.sha256(encrypted_bytes).hexdigest()

    if actual_hash.lower() != expected_hash.lower():
        raise RuntimeError(
            "INTEGRITY FAILURE: downloaded file hash does not match Fabric."
        )

    print("SHA-256 matches Fabric: PASS")

    # 4. Parse the envelope and decrypt only after hash verification.
    print("\n[4/5] Decrypting verified AES-GCM envelope...")

    envelope = json.loads(encrypted_bytes.decode("utf-8"))

    if envelope.get("format") != "AES-256-GCM":
        raise RuntimeError("Unexpected encrypted-file format.")

    nonce = base64.b64decode(envelope["nonce"], validate=True)
    ciphertext_and_tag = base64.b64decode(
        envelope["ciphertext_and_tag"],
        validate=True,
    )

    if len(nonce) != 12:
        raise RuntimeError("AES-GCM nonce must be 12 bytes.")

    if len(ciphertext_and_tag) < 16:
        raise RuntimeError("Encrypted data is too short to contain a GCM tag.")

    aesgcm = AESGCM(key)

    # The existing Flask implementation encrypts with AAD=None.
    plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)

    decoded_event = json.loads(plaintext.decode("utf-8"))

    if not isinstance(decoded_event, dict):
        raise RuntimeError("Decrypted event is not a JSON object.")

    print("AES-GCM decryption: PASS")
    print("Decrypted JSON: PASS")
    print("Plaintext field names:", ", ".join(sorted(decoded_event.keys())))

    # 5. Alter an in-memory copy and ensure authentication fails.
    print("\n[5/5] Testing tamper detection...")

    tampered = bytearray(ciphertext_and_tag)
    tampered[0] ^= 1

    try:
        aesgcm.decrypt(nonce, bytes(tampered), None)
    except InvalidTag:
        print("Tamper detection: PASS (modified ciphertext rejected)")
    else:
        raise RuntimeError(
            "SECURITY FAILURE: modified ciphertext was not rejected."
        )

    print("\n=== ALL VERIFICATION CHECKS PASSED ===")
    print("Original Cloudinary asset was not modified.")
    print("Plaintext and secret keys were not written to disk.")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        # RuntimeError messages in this script are predefined and non-secret.
        print("\nVERIFICATION FAILED:", str(exc))
        raise SystemExit(1)
    except Exception as exc:
        # Do not print URLs, credentials, or exception details.
        print("\nVERIFICATION FAILED:", type(exc).__name__)
        print("A network, authentication, API, or data-processing error occurred.")
        print("Secret values and URLs are not displayed.")
        raise SystemExit(1)