
import os
import json
import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

FILE = Path(__file__).resolve().parent / "encrypted_event.json"

EXPECTED_HASH = (
    "feaf9602226662f8423f73baa69d29b246ad7c28a83d4ef1dd757ae88a37d9aa"
)

def main():
    print("=== Cloud AES-256-GCM Test ===")

    # 1. Load the original encrypted file without modifying it.
    raw = FILE.read_bytes()
    actual_hash = hashlib.sha256(raw).hexdigest()

    print(
        "SHA-256 matches Fabric:",
        actual_hash == EXPECTED_HASH
    )

    if actual_hash != EXPECTED_HASH:
        print("STOP: File hash does not match the expected Fabric hash.")
        return

    # 2. Obtain the original cloud encryption key from this process's
    # environment. Never print the key.
    key_hex = os.environ.get("CLOUD_STORAGE_KEY_HEX", "").strip()

    if len(key_hex) != 64:
        print("Cloud key unavailable in this CMD session.")
        print("Run this test from a process with the original key configured.")
        return

    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        print("Cloud key is not valid hexadecimal.")
        return

    if len(key) != 32:
        print("Cloud key is not 32 bytes.")
        return

    # 3. Decode the encrypted envelope.
    try:
        envelope = json.loads(raw.decode("utf-8"))

        if envelope.get("format") != "AES-256-GCM":
            print("Unexpected encryption format.")
            return

        nonce = base64.b64decode(
            envelope["nonce"], validate=True
        )
        ciphertext = base64.b64decode(
            envelope["ciphertext_and_tag"], validate=True
        )

    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        print("Encrypted envelope is invalid:", type(exc).__name__)
        return

    if len(nonce) != 12 or len(ciphertext) < 16:
        print("Invalid AES-GCM nonce or ciphertext/tag length.")
        return

    aes = AESGCM(key)

    # 4. Decrypt in memory. Cloud encryption used AAD=None.
    try:
        plaintext = aes.decrypt(nonce, ciphertext, None)
        event = json.loads(plaintext.decode("utf-8"))
    except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
        print("Decryption or plaintext validation failed:", type(exc).__name__)
        return

    print("AES-GCM decryption: PASS")
    print("Plaintext is valid JSON:", isinstance(event, (dict, list)))

    if isinstance(event, dict):
        print("JSON field names:", ", ".join(sorted(event.keys())))

    # 5. Flip a bit in a temporary in-memory copy of the ciphertext.
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01

    try:
        aes.decrypt(nonce, bytes(tampered), None)
        print("Tamper detection: FAIL (modified data was accepted)")
    except InvalidTag:
        print("Tamper detection: PASS (modified data was rejected)")

    print("Original encrypted file was not modified.")
    print("Plaintext and encryption key were not written to disk.")

if __name__ == "__main__":
    main()

