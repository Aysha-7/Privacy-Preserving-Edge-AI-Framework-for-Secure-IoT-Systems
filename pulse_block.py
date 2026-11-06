# ==================================================
# STAGE 2: HW-627 PULSE SENSOR (heart-rate anomaly)
# ==================================================
# The ESP32 encrypts each pulse report with the same sensor AES key as the
# DHT11 and posts it here. Finger on the sensor = ANOMALY (demo stand-in
# for an abnormal heart rate); no finger = NORMAL.
#
# Privacy: the BPM and waveform are NEVER written to the CSV, the local
# hash chain, or the dashboard list. They exist only inside the encrypted
# Cloudinary record (together with the patient profile).

PULSE_EVENTS_FILE = BASE_DIR / "pulse_events.jsonl"
PULSE_LOCK = threading.Lock()
PULSE_LIVE = {"status": "NO DATA", "last_seen": None}


@app.post("/api/pulse")
@csrf.exempt
@limiter.limit("30 per minute")
def receive_pulse():
    envelope = request.get_json(silent=True)

    if not isinstance(envelope, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    required = ["device_id", "nonce", "ciphertext", "tag"]

    if any(field not in envelope for field in required):
        return jsonify({"error": "Encrypted envelope is incomplete"}), 400

    device_id = envelope["device_id"]

    if not isinstance(device_id, str) or not device_id or len(device_id) > 64:
        return jsonify({"error": "Invalid device_id"}), 400

    try:
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        tag = base64.b64decode(envelope["tag"], validate=True)

        if len(nonce) != 12 or len(tag) != 16 or len(ciphertext) > 8192:
            return jsonify({"error": "Invalid envelope sizes"}), 400

        plaintext = AES.decrypt(
            nonce,
            ciphertext + tag,
            device_id.encode("utf-8"),
        )
        data = json.loads(plaintext.decode("utf-8"))

    except Exception:
        return jsonify({
            "error": "Encrypted pulse verification or decryption failed"
        }), 400

    if (
        not isinstance(data, dict)
        or data.get("device_id") != device_id
        or data.get("sensor") != "HW-627"
        or data.get("status") not in ("NORMAL", "ANOMALY")
    ):
        return jsonify({"error": "Invalid pulse payload"}), 400

    timestamp = datetime.now(timezone.utc).isoformat()

    if data["status"] == "NORMAL":
        PULSE_LIVE["status"] = "NORMAL"
        PULSE_LIVE["last_seen"] = timestamp

        return jsonify({
            "status": "success",
            "prediction": "NORMAL",
            "timestamp_utc": timestamp,
        }), 200

    # ----------------------------------------------
    # ANOMALY: validate the reading
    # ----------------------------------------------

    try:
        bpm = int(data.get("bpm", 0))
        rate = int(data.get("sample_rate_hz", 50))
        waveform = data.get("waveform", [])

        if not 0 <= bpm <= 250:
            raise ValueError("bpm")

        if not 10 <= rate <= 200:
            raise ValueError("rate")

        if (
            not isinstance(waveform, list)
            or len(waveform) > 300
            or any(
                not isinstance(v, int) or not 0 <= v <= 4095
                for v in waveform
            )
        ):
            raise ValueError("waveform")

    except (TypeError, ValueError):
        return jsonify({"error": "Pulse values are out of range"}), 400

    event_id = "pulse_" + uuid.uuid4().hex

    # Full record: goes ONLY into the encrypted cloud file.
    record = {
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "device_id": device_id,
        "sensor": "HW-627",
        "status": "ANOMALY",
        "finger_detected": True,
        "bpm": bpm,
        "sample_rate_hz": rate,
        "waveform": waveform,
    }

    # Local chain gets a content-free block (no health values).
    try:
        block = append_block({
            "event_id": event_id,
            "timestamp_utc": timestamp,
            "device_id": device_id,
            "event_type": "PULSE_ANOMALY",
        })
    except Exception:
        app.logger.exception("Could not append pulse block to hash chain")
        return jsonify({"error": "Local hash-chain operation failed"}), 500

    PULSE_LIVE["status"] = "ANOMALY"
    PULSE_LIVE["last_seen"] = timestamp

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
            app.logger.exception("Failed to record pulse metadata on Fabric")

    except Exception:
        cloud_status = "failed"
        fabric_status = "skipped"
        app.logger.exception("Failed to upload encrypted pulse event")

    # Metadata only (no BPM, no waveform, no patient details).
    meta = {
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "device_id": "ESP32-PULSE",
        "event_type": "Heart-rate anomaly",
        "cloud_storage_status": cloud_status,
        "cloud_public_id": cloud_public_id,
        "fabric_status": fabric_status,
        "fabric_event_id": fabric_event_id,
        "block_index": block["index"],
    }

    try:
        with PULSE_LOCK:
            with PULSE_EVENTS_FILE.open("a", encoding="utf-8") as file:
                file.write(canonical_json(meta) + "\n")
    except OSError:
        app.logger.exception("Failed to save pulse event metadata")

    send_telegram_alert_async(
        "pulse_anomaly",
        (
            "❤️ ABNORMAL HEART-RATE ALERT\n"
            "A monitored patient needs attention.\n"
            f"Event ID: {event_id}\n"
            f"Time (UTC): {timestamp}\n"
            f"Cloudinary: {cloud_status} | Fabric: {fabric_status}\n"
            "Patient details and the heart-rate trace are not sent in "
            "Telegram. Doctors: sign in to the dashboard, open the "
            "authorised area and unlock the Doctor role."
        ),
    )

    return jsonify({
        "status": "success",
        "prediction": "ANOMALY",
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "block_index": block["index"],
        "cloud_storage_status": cloud_status,
        "fabric_status": fabric_status,
        "fabric_event_id": fabric_event_id,
    }), 201


@app.get("/api/pulse-events")
@dashboard_login_required
def get_pulse_events():
    """Masked pulse-event list for the main dashboard."""

    events = []

    if PULSE_EVENTS_FILE.exists():
        try:
            with PULSE_LOCK:
                lines = PULSE_EVENTS_FILE.read_text(
                    encoding="utf-8"
                ).splitlines()
        except OSError:
            return jsonify({"error": "Could not read pulse events"}), 500

        for line in lines:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    events.append(item)
            except ValueError:
                continue

    events.reverse()

    return jsonify({
        "events": events[:20],
        "count": len(events),
        "live": PULSE_LIVE,
    })

