# ==================================================
# STAGE 4: COMMAND CENTER
# ==================================================
# Real-time trace of every event (each step is reported by the server at
# the moment it happens, Telegram only after Telegram confirms), a live
# mirror of the devices' serial output, an integrity monitor that watches
# the stored evidence, and an attack simulator that really edits that
# evidence so the monitor can be seen catching it.
# No readings, names or images are ever put in a trace.

import collections
import re
from flask import g, has_request_context

S4_LOCK = threading.RLock()
S4_SEQ = [0]
S4_RUNS = collections.deque(maxlen=100)
S4_LOGS = collections.deque(maxlen=600)
S4_LOG_SEQ = [0]
S4_LAST_STEP = {}
S4_LANES = {
    "factory": {"count": 0, "last_seen": 0.0},
    "home": {"count": 0, "last_seen": 0.0},
    "patient": {"count": 0, "last_seen": 0.0},
}
S4_TELEMETRY = {"factory": {}}
S4_LOG_SEEN = {"factory": 0.0, "home": 0.0}
S4_ONLINE_SECONDS = {"factory": 12, "home": 12, "patient": 25}
S4_ATTACK_ENABLED = os.environ.get("ATTACK_DEMO", "1") != "0"

S4_FLOWS = {
    "/api/sensor": ("humidity", "factory", "High humidity", "DHT11 node"),
    "/api/camera-event": ("camera", "home", "Person detected", "ESP32-CAM"),
    "/api/camera-image": ("image", "home", "Anomaly image", "ESP32-CAM"),
    "/api/pulse": ("pulse", "patient", "Heart-rate anomaly", "Pulse node"),
}

S4_SIGNIFICANT = {"encrypt_cloud", "cloud", "fabric", "alert"}


def _s4_bump(run):
    S4_SEQ[0] += 1
    run["seq"] = S4_SEQ[0]


def s4_emit(run, key, status, detail=""):
    """Record one step. A 'running' step is updated in place when it ends."""

    if run is None:
        return

    with S4_LOCK:
        t_ms = int((time.time() - run["_t0"]) * 1000)
        step = None

        for existing in run["steps"]:
            if existing["key"] == key and existing["status"] == "running":
                step = existing
                break

        if step is None:
            run["steps"].append({
                "key": key, "status": status,
                "detail": detail, "t_ms": t_ms,
            })
        else:
            step["status"] = status
            step["t_ms"] = t_ms
            if detail:
                step["detail"] = detail

        if key in S4_SIGNIFICANT and not run["significant"]:
            run["significant"] = True
            S4_LANES[run["lane"]]["count"] += 1
        elif status == "fail":
            run["significant"] = True

        if status in ("ok", "fail", "skipped"):
            S4_LAST_STEP[key] = {"status": status, "t": time.time()}

        _s4_bump(run)


def pipeline_emit(key, status, detail=""):
    run = getattr(g, "pipeline_run", None) if has_request_context() else None
    s4_emit(run, key, status, detail)


def s4_maybe_done(run):
    with S4_LOCK:
        if run["done"] or not run["http_done"] or run["pending"] > 0:
            return

        run["done"] = True
        run["total_ms"] = int((time.time() - run["_t0"]) * 1000)
        _s4_bump(run)


@app.before_request
def _s4_begin():
    flow = S4_FLOWS.get(request.path)

    if flow is None or request.method != "POST":
        return

    run = {
        "id": uuid.uuid4().hex[:10],
        "flow": flow[0], "lane": flow[1], "title": flow[2], "device": flow[3],
        "src": request.remote_addr or "",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "steps": [], "significant": False,
        "done": False, "http": None, "http_done": False, "pending": 0,
        "ref": None, "total_ms": None, "_t0": time.time(),
    }

    g.pipeline_run = run

    with S4_LOCK:
        S4_RUNS.append(run)
        S4_LANES[flow[1]]["last_seen"] = time.time()
        _s4_bump(run)

    s4_emit(
        run, "received", "ok",
        f"Encrypted packet from {flow[3]} at {run['src']} "
        f"({request.content_length or 0} bytes)")


@app.after_request
def _s4_end(response):
    run = getattr(g, "pipeline_run", None)

    if run is not None and not run["http_done"]:
        run["http"] = response.status_code
        run["http_done"] = True

        if response.status_code >= 400:
            reason = ""
            try:
                reason = str((response.get_json(silent=True) or {}).get(
                    "error", ""))[:120]
            except Exception:
                pass

            if not any(st["key"] == "decrypt" for st in run["steps"]):
                s4_emit(run, "decrypt", "fail",
                        f"Rejected (HTTP {response.status_code}). "
                        f"{reason or 'The server refused this packet.'}")

        s4_maybe_done(run)

    return response


@app.teardown_request
def _s4_teardown(_error):
    run = getattr(g, "pipeline_run", None)

    if run is not None and not run["http_done"]:
        run["http"] = 500
        run["http_done"] = True
        s4_maybe_done(run)


# ---- AES objects report decrypt / cloud-encrypt as they really happen

class S4TracedAES:
    def __init__(self, real, kind):
        self._real = real
        self._kind = kind

    def decrypt(self, nonce, data, aad):
        try:
            result = self._real.decrypt(nonce, data, aad)
        except Exception:
            if self._kind == "device":
                pipeline_emit("decrypt", "fail",
                              "Authentication tag INVALID. Packet rejected.")
            raise

        if self._kind == "device":
            pipeline_emit("decrypt", "ok",
                          "AES-256-GCM tag verified. Packet is authentic.")

        return result

    def encrypt(self, nonce, data, aad):
        run = getattr(g, "pipeline_run", None) \
            if has_request_context() else None

        if self._kind == "cloud" and run is not None \
                and run["flow"] == "image" and not run.get("img_block"):
            run["img_block"] = True
            camera_id = "none"
            try:
                camera_id = str((request.get_json(silent=True) or {}).get(
                    "camera_event_id", "none"))[:40]
            except Exception:
                pass

            append_block({
                "event_id": "img_" + uuid.uuid4().hex[:16],
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "device_id": "ESP32-CAM",
                "event_type": "ENCRYPTED_IMAGE",
                "camera_event_id": camera_id,
            })

        result = self._real.encrypt(nonce, data, aad)

        if self._kind == "cloud":
            pipeline_emit(
                "encrypt_cloud", "ok",
                f"Re-encrypted with the cloud key ({len(result)} bytes)")

        return result


AES = S4TracedAES(AES, "device")  # noqa: F811
CAMERA_AES = S4TracedAES(CAMERA_AES, "device")  # noqa: F811
CLOUD_AES = S4TracedAES(CLOUD_AES, "cloud")  # noqa: F811


# ---- Hash chain

_s4_orig_append_block = append_block


def append_block(event):  # noqa: F811
    block = _s4_orig_append_block(event)

    pipeline_emit(
        "chain", "ok",
        f"Block #{block['index']} sealed, fingerprint {block['hash'][:14]}...")

    return block


# Camera events did not write a chain block before; give them one
# (content-free: no confidence, no image, no profile).
_s4_orig_upload_event = upload_encrypted_event_to_cloud


def upload_encrypted_event_to_cloud(event):  # noqa: F811
    if isinstance(event, dict) \
            and str(event.get("event_id", "")).startswith("cam_"):
        append_block({
            "event_id": event["event_id"],
            "timestamp_utc": event.get("timestamp_utc")
            or datetime.now(timezone.utc).isoformat(),
            "device_id": event.get("device_id", "ESP32-CAM"),
            "event_type": "INTRUSION",
        })

    return _s4_orig_upload_event(event)


# ---- Cloudinary

_s4_orig_cloud_upload = cloudinary.uploader.upload


def _s4_cloud_upload(file, *args, **kwargs):
    size = file.getbuffer().nbytes if hasattr(file, "getbuffer") else 0
    pipeline_emit("cloud", "running", "Uploading ciphertext to Cloudinary...")

    try:
        result = _s4_orig_cloud_upload(file, *args, **kwargs)
    except Exception:
        pipeline_emit("cloud", "fail", "Cloudinary upload failed")
        raise

    name = str(result.get("public_id", "")).rsplit("/", 1)[-1]
    pipeline_emit("cloud", "ok",
                  f"{size} bytes of ciphertext stored as {name[:20]}...")

    return result


cloudinary.uploader.upload = _s4_cloud_upload


# ---- Fabric

_s4_orig_fabric = record_event_on_fabric


def record_event_on_fabric(*args, **kwargs):  # noqa: F811
    file_hash = str(kwargs.get("encrypted_file_hash") or (
        args[2] if len(args) > 2 else ""))
    event_id = str(kwargs.get("event_id") or (args[0] if args else ""))

    run = getattr(g, "pipeline_run", None) if has_request_context() else None
    if run is not None:
        run["ref"] = event_id

    pipeline_emit("fabric", "running", "Writing the fingerprint to Fabric...")

    try:
        result = _s4_orig_fabric(*args, **kwargs)
    except Exception:
        pipeline_emit("fabric", "fail", "Fabric did not accept the record")
        raise

    pipeline_emit(
        "fabric", "ok",
        f"Ledger holds SHA-256 {file_hash[:16]}... for {event_id[:18]}...")

    return result


# ---- Telegram: the Alert step finishes only when Telegram confirms

def send_telegram_alert_async(alert_type, message):  # noqa: F811
    run = getattr(g, "pipeline_run", None) if has_request_context() else None

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        s4_emit(run, "alert", "skipped", "Telegram is not set up on this PC")
        return

    now = time.monotonic()

    with _TELEGRAM_ALERT_LOCK:
        previous = _TELEGRAM_LAST_SENT.get(alert_type, 0.0)

        if now - previous < TELEGRAM_ALERT_COOLDOWN_SECONDS:
            s4_emit(run, "alert", "skipped",
                    "Cooldown: a similar alert was sent a moment ago")
            return

        _TELEGRAM_LAST_SENT[alert_type] = now

    s4_emit(run, "alert", "running", "Sending the alert to Telegram...")

    if run is not None:
        with S4_LOCK:
            run["pending"] += 1

    def _send():
        started = time.time()

        try:
            response = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
                "/sendMessage",
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": message,
                    "disable_web_page_preview": True,
                },
                timeout=10,
            )
            response.raise_for_status()

            if not response.json().get("ok"):
                raise RuntimeError("not confirmed")

            s4_emit(run, "alert", "ok",
                    "Telegram confirmed delivery in "
                    f"{int((time.time() - started) * 1000)} ms")

        except Exception:
            # Never log the URL: it contains the bot token.
            app.logger.warning("Telegram %s alert failed.", alert_type)
            s4_emit(run, "alert", "fail", "Telegram did not confirm")

            with _TELEGRAM_ALERT_LOCK:
                _TELEGRAM_LAST_SENT.pop(alert_type, None)

        finally:
            if run is not None:
                with S4_LOCK:
                    run["pending"] -= 1
                s4_maybe_done(run)

    threading.Thread(target=_send, name=f"telegram-{alert_type}",
                     daemon=True).start()


# ==================================================
# DEVICE SERIAL MIRROR  (/api/device-log)
# ==================================================

_S4_TEMP = re.compile(r"Temperature:\s*(-?[\d.]+)")
_S4_HUM = re.compile(r"Humidity:\s*([\d.]+)")
_S4_PRED = re.compile(r"Final prediction:\s*(\w+)")
_S4_SCORE = re.compile(
    r"TinyML scores:\s*NORMAL=([\d.]+),\s*HIGH_HUMIDITY=([\d.]+)")
_S4_MS = re.compile(r"Sample processing time:\s*(\d+)\s*ms")


def _s4_log_lane(device_id, text):
    if device_id == "ESP32-CAM":
        return "home"

    return "patient" if text.startswith("[PULSE]") else "factory"


def _s4_parse_telemetry(lane, text):
    if lane != "factory":
        return

    tel = S4_TELEMETRY["factory"]
    m = _S4_TEMP.search(text)
    if m:
        tel["temperature"] = float(m.group(1))
    m = _S4_HUM.search(text)
    if m and "Quantized" not in text:
        tel["humidity"] = float(m.group(1))
    m = _S4_PRED.search(text)
    if m:
        tel["prediction"] = m.group(1)
    m = _S4_SCORE.search(text)
    if m:
        tel["score_normal"] = float(m.group(1))
        tel["score_high"] = float(m.group(2))
    m = _S4_MS.search(text)
    if m:
        tel["inference_ms"] = int(m.group(1))
    tel["t"] = time.time()


def s4_log_problem(device_id, why):
    """Show a refused log packet in the console panel and the Flask window."""

    lane = "home" if device_id == "ESP32-CAM" else "factory"
    text = f"[server] log packet from {device_id} refused: {why}"
    app.logger.warning(text)

    with S4_LOCK:
        S4_LOG_SEQ[0] += 1
        S4_LOGS.append({"seq": S4_LOG_SEQ[0], "t": time.time(),
                        "lane": lane, "text": text + " error"})


@app.post("/api/device-log")
@csrf.exempt
@limiter.limit("90 per minute")
def receive_device_log():
    envelope = request.get_json(silent=True)

    if not isinstance(envelope, dict) or any(
            f not in envelope for f in ("device_id", "nonce",
                                        "ciphertext", "tag")):
        s4_log_problem("?", "a log packet had missing fields")
        return jsonify({"error": "Incomplete log packet"}), 400

    device_id = envelope["device_id"]

    if device_id not in ("ESP32_01", "ESP32-CAM"):
        s4_log_problem("?", f"unknown device name {str(device_id)[:20]!r}")
        return jsonify({"error": "Unknown device"}), 400

    try:
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        tag = base64.b64decode(envelope["tag"], validate=True)

        if len(nonce) != 12 or len(tag) != 16 or len(ciphertext) > 16384:
            raise ValueError("size")

        if device_id == "ESP32-CAM":
            plaintext = CAMERA_AES.decrypt(
                nonce, ciphertext + tag, b"ESP32-CAM:LOG")
        else:
            plaintext = AES.decrypt(
                nonce, ciphertext + tag, device_id.encode("utf-8"))

        data = json.loads(plaintext.decode("utf-8"))
        lines = data["lines"]

        if data.get("kind") != "serial" or not isinstance(lines, list) \
                or len(lines) > 40:
            raise ValueError("shape")

    except Exception as exc:
        why = ("wrong key or changed data (check the key in the sketch)"
               if exc.__class__.__name__ == "InvalidTag"
               else f"bad packet ({exc.__class__.__name__})")
        s4_log_problem(device_id, why)
        return jsonify({"error": "Log packet failed verification"}), 400

    now = time.time()
    seen_lane = "home" if device_id == "ESP32-CAM" else "factory"

    with S4_LOCK:
        S4_LOG_SEEN[seen_lane] = now
        S4_LANES[seen_lane]["last_seen"] = now

        for raw in lines:
            if not isinstance(raw, str):
                continue

            text = "".join(
                c for c in raw if c.isprintable())[:200].strip()

            if not text:
                continue

            lane = _s4_log_lane(device_id, text)
            S4_LOG_SEQ[0] += 1
            S4_LOGS.append({
                "seq": S4_LOG_SEQ[0], "t": now, "lane": lane, "text": text,
            })
            S4_LANES[lane]["last_seen"] = now
            _s4_parse_telemetry(lane, text)

    return jsonify({"status": "ok"}), 200


# ==================================================
# INTEGRITY MONITOR AND ATTACK SIMULATOR
# ==================================================

S4_INTEGRITY = {
    "state": "intact", "findings": [], "checked": 0.0,
    "chain_blocks": 0, "cloud_checked": 0, "cloud_checked_at": 0.0,
    "alerted": False, "since": None,
}
S4_HISTORY = collections.deque(maxlen=30)
S4_ATTACK_LOG = collections.deque(maxlen=60)
S4_ATTACK_STATE = {"chain": None, "cloud": None, "busy": False,
                   "busy_since": 0.0}
S4_ACK = {}  # event id -> fingerprint the owner accepted
S4_CLOUD_FINDINGS = {}
S4_FORCE_CLOUD = threading.Event()
S4_BACKUP_DIR = BASE_DIR / "tamper_backup"


def s4_save_backup():
    """Keep the untouched originals on disk so a restart cannot lose them."""

    try:
        S4_BACKUP_DIR.mkdir(exist_ok=True)
        chain = S4_ATTACK_STATE["chain"]
        cloud = S4_ATTACK_STATE["cloud"]
        chain_file = S4_BACKUP_DIR / "chain.json"
        cloud_meta = S4_BACKUP_DIR / "cloud.json"
        cloud_bin = S4_BACKUP_DIR / "cloud.bin"

        if chain:
            chain_file.write_text(json.dumps(chain), encoding="utf-8")
        elif chain_file.exists():
            chain_file.unlink()

        if cloud:
            cloud_bin.write_bytes(cloud["original"])
            cloud_meta.write_text(json.dumps({
                "reference": cloud["reference"],
                "event_id": cloud["event_id"]}), encoding="utf-8")
        else:
            for item in (cloud_meta, cloud_bin):
                if item.exists():
                    item.unlink()
    except OSError:
        app.logger.exception("Could not save tamper backup")


def s4_load_backup():
    try:
        chain_file = S4_BACKUP_DIR / "chain.json"
        cloud_meta = S4_BACKUP_DIR / "cloud.json"
        cloud_bin = S4_BACKUP_DIR / "cloud.bin"

        if chain_file.exists():
            S4_ATTACK_STATE["chain"] = json.loads(
                chain_file.read_text(encoding="utf-8"))

        if cloud_meta.exists() and cloud_bin.exists():
            meta = json.loads(cloud_meta.read_text(encoding="utf-8"))
            meta["original"] = cloud_bin.read_bytes()
            S4_ATTACK_STATE["cloud"] = meta
    except (OSError, ValueError):
        app.logger.exception("Could not load tamper backup")


s4_load_backup()
S4_STEP_SECONDS = 1.1


def s4_alog(actor, text):
    with S4_LOCK:
        S4_ATTACK_LOG.append({"t": time.time(), "actor": actor, "text": text})


def s4_chain_check():
    """Recompute every block. Returns (blocks, findings)."""

    try:
        with CHAIN_LOCK:
            blocks = read_chain()
    except Exception:
        return 0, [{
            "kind": "chain", "index": None,
            "summary": "The evidence log cannot be read.",
            "expected": "", "found": "",
        }]

    findings = []
    previous = GENESIS_HASH

    for i, block in enumerate(blocks):
        event = block.get("event", {}) if isinstance(block, dict) else {}
        label = (
            event.get("prediction") or event.get("event_type") or "event")

        if block.get("previous_hash") != previous:
            findings.append({
                "kind": "chain", "index": i,
                "summary": (
                    f"Block #{i} is no longer linked to block #{i - 1}. "
                    "An earlier block was changed."),
                "expected": str(previous),
                "found": str(block.get("previous_hash")),
            })

        recomputed = calculate_block_hash(block)

        if block.get("hash") != recomputed:
            findings.append({
                "kind": "chain", "index": i,
                "summary": (
                    f"Block #{i} ({label}) was edited. Its contents no "
                    "longer match its fingerprint."),
                "expected": str(block.get("hash")),
                "found": recomputed,
            })

        previous = block.get("hash")

    return len(blocks), findings[:6]


def s4_ledger_hash(event_id):
    """Trusted hash from Fabric, or None when it is not on the ledger."""

    if not FABRIC_GATEWAY_TOKEN:
        return None

    try:
        response = requests.get(
            FABRIC_GATEWAY_URL.rstrip("/") + "/" + event_id,
            headers={"Authorization": f"Bearer {FABRIC_GATEWAY_TOKEN}"},
            timeout=10)
        response.raise_for_status()
        data = response.json()
        event = data.get("event", {})

        if data.get("status") != "found" \
                or event.get("eventId") != event_id:
            return None

        value = str(event.get("encryptedFileHash", "")).lower()
        reference = str(event.get("cloudReference", ""))

        if len(value) == 64 and reference.startswith(
                "encrypted_iot_events/"):
            return value, reference

    except Exception:
        return None

    return None


def s4_download(reference):
    asset = cloudinary.api.resource(reference, resource_type="raw")
    response = requests.get(asset["secure_url"], timeout=20)
    response.raise_for_status()

    return response.content


def s4_cloud_scan(limit=2):
    """Compare the newest cloud files with the hashes held on Fabric."""

    checked = 0
    index = list(reversed(vault_read_index()))
    known = [e for e in index if e.get("event_id") in S4_CLOUD_FINDINGS]

    for entry in known + index:
        if checked >= limit + len(known):
            break

        event_id = entry.get("event_id", "")
        ledger = s4_ledger_hash(event_id)

        if ledger is None:
            continue

        expected, reference = ledger
        checked += 1

        try:
            actual = hashlib.sha256(s4_download(reference)).hexdigest()
        except Exception:
            continue

        if actual != expected and S4_ACK.get(event_id) == actual:
            S4_CLOUD_FINDINGS.pop(event_id, None)
        elif actual != expected:
            S4_CLOUD_FINDINGS[event_id] = {
                "kind": "cloud", "index": None,
                "summary": (
                    f"The encrypted evidence file {event_id[:22]}... in "
                    "the cloud was replaced. Its fingerprint no longer "
                    "matches the Fabric ledger."),
                "expected": expected, "found": actual,
            }
        else:
            S4_CLOUD_FINDINGS.pop(event_id, None)

    S4_INTEGRITY["cloud_checked"] = checked
    S4_INTEGRITY["cloud_checked_at"] = time.time()


def s4_update_state():
    blocks, chain_findings = s4_chain_check()

    with S4_LOCK:
        findings = chain_findings + list(S4_CLOUD_FINDINGS.values())
        was = S4_INTEGRITY["state"]

        S4_INTEGRITY["checked"] = time.time()
        S4_INTEGRITY["chain_blocks"] = blocks
        S4_INTEGRITY["findings"] = findings

        if findings and was != "compromised":
            S4_INTEGRITY["state"] = "compromised"
            S4_INTEGRITY["since"] = time.time()
            S4_HISTORY.append({
                "t": time.time(), "kind": "alarm",
                "text": findings[0]["summary"]})
            send_alert = True
        elif not findings and was == "compromised":
            S4_INTEGRITY["state"] = "intact"
            S4_HISTORY.append({
                "t": time.time(), "kind": "ok",
                "text": "Evidence verified again. Everything matches."})
            send_alert = False
            s4_alog("MONITOR", "All evidence matches its fingerprints again.")
            send_telegram_alert_async(
                "tamper_cleared",
                "✅ Evidence verified again. All stored records match "
                "their fingerprints.")
        else:
            send_alert = False

        first = findings[0] if findings else None

    if send_alert and first:
        s4_alog("MONITOR", "ALARM: " + first["summary"])

        with _TELEGRAM_ALERT_LOCK:
            _TELEGRAM_LAST_SENT.pop("tamper_detected", None)

        send_telegram_alert_async(
            "tamper_detected",
            "🚨 TAMPERING DETECTED\n"
            f"{first['summary']}\n"
            f"Expected fingerprint: {first['expected'][:16]}...\n"
            f"Found fingerprint:    {first['found'][:16]}...\n"
            "The stored evidence no longer matches. Open the Command "
            "Center to review.")


def _s4_monitor_loop():
    last_cloud = 0.0

    while True:
        try:
            if S4_FORCE_CLOUD.is_set() or time.time() - last_cloud > 12:
                S4_FORCE_CLOUD.clear()
                last_cloud = time.time()
                s4_cloud_scan()

            s4_update_state()
        except Exception:
            app.logger.exception("Integrity monitor error")

        time.sleep(0.7)


threading.Thread(target=_s4_monitor_loop, name="integrity-monitor",
                 daemon=True).start()


# ---- Attack simulator: performs REAL edits on the stored evidence

def _s4_chain_lines():
    text = CHAIN_FILE.read_text(encoding="utf-8")
    lines = text.split("\n")
    blocks = []

    for line_index, line in enumerate(lines):
        if not line.strip():
            continue

        try:
            blocks.append((line_index, json.loads(line)))
        except ValueError:
            continue

    return lines, blocks


def s4_attack_chain(smart):
    s4_alog("ATTACKER", "Gained access to the server's evidence log.")
    time.sleep(S4_STEP_SECONDS)

    with CHAIN_LOCK:
        lines, blocks = _s4_chain_lines()
        needed = 2

        if len(blocks) < needed:
            s4_alog("SYSTEM", "Not enough chain blocks yet. Trigger a few "
                              "events first, then try again.")
            return

        wanted = [b for b in blocks
                  if b[1].get("event", {}).get("prediction")
                  == "HIGH_HUMIDITY"]

        if smart:
            wanted = [b for b in wanted if b[1]["index"] < len(blocks) - 1]

        target = wanted[-1] if wanted else blocks[-2]

    s4_alog("ATTACKER", "Searching for a recent alert to erase...")
    time.sleep(S4_STEP_SECONDS)

    line_index, block = target
    event = block.get("event", {})
    original_line = lines[line_index]

    if event.get("prediction") == "HIGH_HUMIDITY":
        event["prediction"] = "NORMAL"
        event["humidity_percent"] = 52.0
        change = "HIGH_HUMIDITY became NORMAL (the alert is hidden)"
    elif "event_type" in event:
        event["event_type"] = "ROUTINE_CHECK"
        change = "the event type was rewritten to ROUTINE_CHECK"
    else:
        event["device_id"] = "UNKNOWN"
        change = "the device name was overwritten"

    s4_alog("ATTACKER",
            f"Found block #{block['index']}: {change}.")
    time.sleep(S4_STEP_SECONDS)

    if smart:
        block["hash"] = calculate_block_hash(block)
        s4_alog("ATTACKER", "Recalculating the block's fingerprint so it "
                            "looks valid...")
        time.sleep(S4_STEP_SECONDS)

    with CHAIN_LOCK:
        lines, blocks = _s4_chain_lines()

        if line_index >= len(lines) or lines[line_index] != original_line:
            s4_alog("SYSTEM", "The log changed while attacking. Try again.")
            return

        lines[line_index] = canonical_json(block)
        CHAIN_FILE.write_text("\n".join(lines), encoding="utf-8")

    with S4_LOCK:
        S4_ATTACK_STATE["chain"] = {
            "line_index": line_index, "original": original_line,
            "block_index": block["index"],
        }
        s4_save_backup()

    s4_alog("ATTACKER", "File saved. The attacker believes nobody noticed.")


def s4_attack_cloud():
    s4_alog("ATTACKER", "Logged in to the cloud storage account.")
    time.sleep(S4_STEP_SECONDS)

    target = None

    for entry in reversed(vault_read_index()):
        ledger = s4_ledger_hash(entry.get("event_id", ""))

        if ledger:
            target = (entry["event_id"], ledger[1])
            break

    if target is None:
        s4_alog("SYSTEM", "No encrypted evidence on the ledger yet. "
                          "Trigger an event first, then try again.")
        return

    event_id, reference = target
    s4_alog("ATTACKER", f"Found evidence file {event_id[:22]}...")
    time.sleep(S4_STEP_SECONDS)

    try:
        original = s4_download(reference)
        marker = b'"ciphertext_and_tag":"'
        position = original.index(marker) + len(marker)
        flipped = b"A" if original[position:position + 1] != b"A" else b"B"
        tampered = original[:position] + flipped + original[position + 1:]
    except Exception:
        s4_alog("SYSTEM", "Could not read the evidence file. Try again.")
        return

    s4_alog("ATTACKER", "Changing one byte of the encrypted file and "
                        "uploading it back...")
    time.sleep(S4_STEP_SECONDS)

    try:
        cloudinary.uploader.upload(
            io.BytesIO(tampered), resource_type="raw",
            public_id=reference, overwrite=True, invalidate=True)
    except Exception:
        s4_alog("SYSTEM", "Cloud upload failed. Nothing was changed.")
        return

    with S4_LOCK:
        S4_ATTACK_STATE["cloud"] = {
            "reference": reference, "original": original,
            "event_id": event_id,
        }
        s4_save_backup()

    s4_alog("ATTACKER", "Upload finished. The file now holds forged data.")
    time.sleep(S4_STEP_SECONDS)
    S4_FORCE_CLOUD.set()


def s4_reseal_chain():
    """Owner decision when no saved original exists: keep a copy of the
    damaged log, then recompute every link so the chain verifies again."""

    with CHAIN_LOCK:
        text = CHAIN_FILE.read_text(encoding="utf-8")
        archive = CHAIN_FILE.with_name(
            CHAIN_FILE.name + ".tampered_" + time.strftime("%Y%m%d_%H%M%S"))
        archive.write_text(text, encoding="utf-8")
        _lines, blocks = _s4_chain_lines()
        previous = GENESIS_HASH
        out = []

        for position, (_line_index, block) in enumerate(blocks):
            block["index"] = position
            block["previous_hash"] = previous
            block["hash"] = calculate_block_hash(block)
            previous = block["hash"]
            out.append(canonical_json(block))

        CHAIN_FILE.write_text("\n".join(out) + "\n", encoding="utf-8")

    return archive.name


def s4_restore():
    restored = False

    with S4_LOCK:
        chain_state = S4_ATTACK_STATE["chain"]
        cloud_state = S4_ATTACK_STATE["cloud"]

    if chain_state:
        with CHAIN_LOCK:
            lines, _blocks = _s4_chain_lines()

            if chain_state["line_index"] < len(lines):
                lines[chain_state["line_index"]] = chain_state["original"]
                CHAIN_FILE.write_text("\n".join(lines), encoding="utf-8")
                restored = True

        with S4_LOCK:
            S4_ATTACK_STATE["chain"] = None

    if cloud_state:
        try:
            cloudinary.uploader.upload(
                io.BytesIO(cloud_state["original"]), resource_type="raw",
                public_id=cloud_state["reference"],
                overwrite=True, invalidate=True)
            restored = True
        except Exception:
            s4_alog("SYSTEM", "Could not restore the cloud file.")

        with S4_LOCK:
            S4_ATTACK_STATE["cloud"] = None
            S4_CLOUD_FINDINGS.pop(cloud_state["event_id"], None)

        S4_FORCE_CLOUD.set()

    s4_save_backup()

    if restored:
        s4_alog("SYSTEM", "Evidence restored from the untouched copy.")

    # Anything still wrong has no saved original (for example it was
    # tampered before this version was running). Repair it as the owner.
    blocks, chain_findings = s4_chain_check()

    if chain_findings:
        try:
            name = s4_reseal_chain()
            s4_alog("SYSTEM",
                    "No saved original for the log. The damaged log was "
                    f"archived as {name} and the chain was re-sealed.")
            restored = True
        except Exception:
            app.logger.exception("Re-seal failed")
            s4_alog("SYSTEM", "Could not repair the log. See the Flask window.")

    S4_FORCE_CLOUD.set()
    time.sleep(1.5)

    with S4_LOCK:
        leftovers = list(S4_CLOUD_FINDINGS.items()) if cloud_state is None \
            else []

    for event_id, finding in leftovers:
        S4_ACK[event_id] = finding["found"]
        S4_CLOUD_FINDINGS.pop(event_id, None)
        s4_alog("SYSTEM",
                f"Cloud file {event_id[:22]}... cannot be recovered (no saved "
                "original). It is marked as reviewed and should not be trusted.")
        restored = True

    if not restored:
        s4_alog("SYSTEM", "Everything already matches. Nothing to repair.")

    s4_update_state()


@app.post("/api/attack/<kind>")
@dashboard_login_required
def s4_attack(kind):
    if not S4_ATTACK_ENABLED:
        return jsonify({"error": "Attack simulator is disabled."}), 403

    body = request.get_json(silent=True) or {}

    if body.get("confirm") != "ATTACK":
        return jsonify({"error": "Confirmation missing."}), 400

    if kind not in ("chain", "chain_smart", "cloud", "restore"):
        return jsonify({"error": "Unknown action."}), 404

    with S4_LOCK:
        if S4_ATTACK_STATE["busy"] \
                and time.time() - S4_ATTACK_STATE["busy_since"] < 40:
            return jsonify({"error": "Another action is still running. "
                            "Wait a few seconds and try again."}), 409

        S4_ATTACK_STATE["busy"] = True
        S4_ATTACK_STATE["busy_since"] = time.time()

    def run():
        try:
            if kind == "chain":
                s4_attack_chain(False)
            elif kind == "chain_smart":
                s4_attack_chain(True)
            elif kind == "cloud":
                s4_attack_cloud()
            else:
                s4_restore()
        except Exception:
            app.logger.exception("Attack simulator error")
            s4_alog("SYSTEM", "The simulator hit an error.")
        finally:
            S4_ATTACK_STATE["busy"] = False

    threading.Thread(target=run, name="attack-sim", daemon=True).start()

    return jsonify({"started": True})


# ==================================================
# LIVE FEED FOR THE PAGE
# ==================================================

def _s4_health():
    def info(key):
        item = S4_LAST_STEP.get(key)

        if not item:
            return {"state": "idle", "age": None}

        return {
            "state": "ok" if item["status"] == "ok" else "bad",
            "age": int(time.time() - item["t"]),
        }

    return {
        "flask": {"state": "ok", "age": 0},
        "chain": {
            "state": "ok" if S4_INTEGRITY["state"] == "intact" else "bad",
            "age": int(time.time() - S4_INTEGRITY["checked"])
            if S4_INTEGRITY["checked"] else None,
        },
        "fabric": info("fabric"),
        "cloud": info("cloud"),
        "telegram": info("alert"),
    }


@app.get("/api/live")
@dashboard_login_required
def s4_live():
    run_since = request.args.get("run_since", default=0, type=int)
    log_since = request.args.get("log_since", default=0, type=int)
    now = time.time()

    with S4_LOCK:
        runs = [
            {k: v for k, v in run.items() if not k.startswith("_")}
            for run in S4_RUNS
            if run["seq"] > run_since and run["significant"]
        ]

        logs = [entry for entry in S4_LOGS if entry["seq"] > log_since]

        if log_since == 0:
            logs = logs[-80:]

        integrity = {
            "state": S4_INTEGRITY["state"],
            "findings": list(S4_INTEGRITY["findings"]),
            "since": S4_INTEGRITY["since"],
            "checked_age": int(now - S4_INTEGRITY["checked"])
            if S4_INTEGRITY["checked"] else None,
            "chain_blocks": S4_INTEGRITY["chain_blocks"],
            "cloud_checked": S4_INTEGRITY["cloud_checked"],
            "cloud_age": int(now - S4_INTEGRITY["cloud_checked_at"])
            if S4_INTEGRITY["cloud_checked_at"] else None,
            "history": list(S4_HISTORY)[-8:],
            "attack_log": list(S4_ATTACK_LOG)[-24:],
            "attack_busy": bool(
                S4_ATTACK_STATE["busy"]
                and now - S4_ATTACK_STATE["busy_since"] < 40),
            "attack_enabled": S4_ATTACK_ENABLED,
            "has_tamper": bool(
                S4_ATTACK_STATE["chain"] or S4_ATTACK_STATE["cloud"]),
        }

        lanes = {
            name: {
                "count": data["count"],
                "age": int(now - data["last_seen"])
                if data["last_seen"] else None,
                "online": bool(
                    data["last_seen"]
                    and now - data["last_seen"] <= S4_ONLINE_SECONDS[name]),
                "log_age": int(now - S4_LOG_SEEN[name])
                if S4_LOG_SEEN.get(name) else None,
            }
            for name, data in S4_LANES.items()
        }

        telemetry = dict(S4_TELEMETRY["factory"])

        if telemetry.get("t"):
            telemetry["age"] = int(now - telemetry["t"])

        payload = {
            "run_seq": S4_SEQ[0],
            "log_seq": S4_LOG_SEQ[0],
            "now": now,
            "runs": runs,
            "logs": logs,
            "integrity": integrity,
            "lanes": lanes,
            "telemetry": telemetry,
            "health": _s4_health(),
        }

    response = jsonify(payload)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/pipeline")
@dashboard_login_required
def pipeline_page():
    from flask_wtf.csrf import generate_csrf

    return Response(
        COMMAND_PAGE.replace("__CSRF__", generate_csrf()),
        mimetype="text/html",
        headers={"Cache-Control": "no-store"},
    )


# The main dashboard must never decrypt anything: decryption lives only in
# the authorised area.
def _s4_no_decrypt(event_id):
    return jsonify({
        "error": "Decryption is only available in the authorised area."
    }), 403


app.view_functions["recover_verified_image"] = dashboard_login_required(
    _s4_no_decrypt)
COMMAND_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="csrf" content="__CSRF__">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Command Center</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,100..900&family=JetBrains+Mono:wght@500;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --paper:#EEF0F4; --ink:#10131A; --white:#FFFFFF; --mute:#5A6372;
  --fac:#FFB000; --home:#00C2A8; --pat:#FF3D81; --bad:#E5231B; --good:#14A44D;
  --fac-d:#7A5400; --home-d:#00695C; --pat-d:#A3003F;
  --disp:"Archivo",system-ui,"Segoe UI",Arial,sans-serif;
  --mono:"JetBrains Mono",ui-monospace,Consolas,"Courier New",monospace;
}
*{box-sizing:border-box;margin:0}
html{background:var(--paper)}
body{font-family:var(--disp);font-weight:600;color:var(--ink);background:var(--paper);min-height:100vh;
  background-image:radial-gradient(var(--ink) 1px,transparent 1.2px);background-size:26px 26px;background-position:-6px -6px}
body::before{content:"";position:fixed;inset:0;background:var(--paper);opacity:.93;z-index:-1}
a{color:inherit}
.wrap{max-width:1500px;margin:0 auto;padding:16px 20px 40px}

/* ---------- top bar ---------- */
.top{display:flex;align-items:center;gap:18px;flex-wrap:wrap;margin-bottom:16px}
.brand{font-weight:900;font-stretch:112%;font-size:38px;letter-spacing:-.02em;line-height:1}
.brand small{display:block;font-size:15px;font-weight:700;letter-spacing:0;color:var(--mute);margin-top:6px;font-stretch:100%}
.sp{flex:1}
.leds{display:flex;gap:8px;flex-wrap:wrap}
.led{display:flex;align-items:center;gap:8px;background:var(--white);border:3px solid var(--ink);padding:7px 12px;font-size:16px;font-weight:800;box-shadow:4px 4px 0 var(--ink)}
.led i{width:14px;height:14px;border-radius:50%;background:#B7BDC8;border:2px solid var(--ink);flex:none}
.led.ok i{background:var(--good);animation:ledp 2.4s ease-in-out infinite}
.led.bad i{background:var(--bad);animation:ledb .6s steps(2) infinite}
.led small{font-size:13px;font-weight:700;color:var(--mute);font-family:var(--mono)}
@keyframes ledp{50%{box-shadow:0 0 0 5px rgba(20,164,77,.25)}}
@keyframes ledb{50%{opacity:.25}}
.btn{font:800 16px var(--disp);background:var(--white);border:3px solid var(--ink);padding:9px 14px;cursor:pointer;box-shadow:4px 4px 0 var(--ink);color:var(--ink);text-decoration:none;display:inline-block}
.btn:hover{transform:translate(2px,2px);box-shadow:2px 2px 0 var(--ink)}
.btn:active{transform:translate(4px,4px);box-shadow:0 0 0 var(--ink)}
.btn:focus-visible,.tab:focus-visible{outline:4px solid var(--pat);outline-offset:2px}
.btn[disabled]{opacity:.4;pointer-events:none}

/* ---------- lanes ---------- */
.lane{--c:var(--fac);--cd:var(--fac-d);background:var(--white);border:4px solid var(--ink);box-shadow:8px 8px 0 var(--ink);margin-bottom:22px;display:grid;grid-template-columns:270px 1fr;position:relative}
.lane.home{--c:var(--home);--cd:var(--home-d)}
.lane.patient{--c:var(--pat);--cd:var(--pat-d)}
.lhead{background:var(--c);border-right:4px solid var(--ink);padding:16px 18px;display:flex;flex-direction:column;gap:8px}
.lhead h2{font-size:34px;font-weight:900;font-stretch:105%;line-height:1;letter-spacing:-.02em}
.lhead .dev{font-size:17px;font-weight:800}
.pill{align-self:flex-start;font:800 15px var(--disp);background:var(--ink);color:var(--white);padding:5px 10px;display:inline-flex;gap:8px;align-items:center}
.pill i{width:10px;height:10px;border-radius:50%;background:#7a8394}
.pill.live i{background:#3DFF8A;animation:ledp 1.6s infinite}
.lhead .cnt{margin-top:auto;font-size:15px;font-weight:800}
.lhead .cnt b{font-size:56px;font-weight:900;font-stretch:100%;display:block;line-height:1}
.lbody{padding:16px 20px 18px;min-width:0}
.meta{display:flex;flex-wrap:wrap;gap:6px 22px;font-family:var(--mono);font-size:15px;font-weight:700;margin-bottom:14px;min-height:22px}
.meta b{background:var(--ink);color:var(--white);padding:1px 7px}
.idle-msg{font-size:24px;font-weight:800}

.track{position:relative;display:grid;grid-template-columns:repeat(7,1fr);gap:0;margin:6px 0 10px}
.track::before{content:"";position:absolute;left:7%;right:7%;top:37px;height:8px;background:repeating-linear-gradient(90deg,var(--ink) 0 10px,transparent 10px 20px);opacity:.25}
.lane.waiting .track::before{animation:march 1.1s linear infinite}
@keyframes march{to{background-position:20px 0}}
.fill{position:absolute;left:7%;top:37px;height:8px;background:var(--ink);width:0;transition:width .35s cubic-bezier(.2,.9,.2,1)}
.fill::after{content:"";position:absolute;right:-9px;top:-5px;width:18px;height:18px;background:var(--c);border:3px solid var(--ink);border-radius:50%;opacity:0}
.lane.live .fill::after{opacity:1;animation:headp .7s ease-in-out infinite alternate}
@keyframes headp{to{transform:scale(1.35)}}
.st{position:relative;text-align:center;padding:0 4px;z-index:1}
.node{width:82px;height:82px;margin:0 auto;border:4px solid var(--ink);background:var(--white);display:grid;place-items:center;font-size:36px;font-weight:900;transition:background .15s}
.st .nm{margin-top:10px;font-size:19px;font-weight:900;line-height:1.1}
.st .sub{font-size:14px;font-weight:700;color:var(--mute);margin-top:2px;font-family:var(--mono);min-height:18px}
.st.running .node{background:repeating-linear-gradient(-45deg,var(--c) 0 10px,var(--white) 10px 20px);animation:stripe .6s linear infinite}
@keyframes stripe{to{background-position:28px 0}}
.st.ok .node{background:var(--c);animation:stamp .42s cubic-bezier(.2,1.8,.4,1)}
@keyframes stamp{0%{transform:scale(1.35) rotate(-6deg)}100%{transform:none}}
.st.ok .node::after{content:"\2713"}
.st.fail .node{background:var(--bad);color:var(--white);animation:shake .4s}
.st.fail .node::after{content:"\2715"}
.st.skipped .node{background:repeating-linear-gradient(45deg,#D5D9E0 0 6px,var(--white) 6px 12px);color:var(--mute)}
.st.skipped .node::after{content:"\2013"}
.st.running .node::after{content:""}
@keyframes shake{25%{transform:translateX(-7px)}75%{transform:translateX(7px)}}
.lane.flash{animation:laneflash .9s ease-out}
@keyframes laneflash{0%{box-shadow:0 0 0 0 var(--c),8px 8px 0 var(--ink)}40%{box-shadow:0 0 0 14px var(--c),8px 8px 0 var(--ink)}100%{box-shadow:0 0 0 0 transparent,8px 8px 0 var(--ink)}}

.steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:4px 26px;margin-top:8px;border-top:3px solid var(--ink);padding-top:10px}
.steps div{font-size:17px;font-weight:700;line-height:1.3;display:flex;gap:10px}
.steps b{font-family:var(--mono);font-size:14px;background:var(--c);border:2px solid var(--ink);padding:0 6px;height:24px;flex:none;font-weight:800;white-space:nowrap}
.steps .bad{color:var(--bad)}
.hist{display:flex;gap:6px;margin-top:12px;align-items:center;font-size:15px;font-weight:800;flex-wrap:wrap}
.hist span.h{width:26px;height:26px;border:3px solid var(--ink);background:var(--c);cursor:pointer}
.hist span.h.f{background:var(--bad)}
.hist span.h.sel{outline:4px solid var(--ink);outline-offset:2px}

.tele{display:flex;gap:26px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px}
.tele .big{font-size:64px;font-weight:900;font-stretch:100%;line-height:.9;letter-spacing:-.03em}
.tele .big small{font-size:24px;font-weight:800}
.tele .lbl{font-size:16px;font-weight:800;color:var(--mute)}
.bars{display:flex;flex-direction:column;gap:6px;min-width:260px;flex:1;max-width:420px}
.bar{display:grid;grid-template-columns:130px 1fr 56px;align-items:center;gap:8px;font-size:16px;font-weight:800}
.bar div{height:20px;border:3px solid var(--ink);background:var(--white)}
.bar div i{display:block;height:100%;background:var(--c);width:0;transition:width .4s}
.bar span{font-family:var(--mono);font-size:15px;text-align:right}

/* ---------- lower grid ---------- */
.low{display:grid;grid-template-columns:1.15fr 1fr;gap:22px;align-items:start}
.panel{background:var(--white);border:4px solid var(--ink);box-shadow:8px 8px 0 var(--ink);min-width:0}
.panel>h3{font-size:26px;font-weight:900;padding:10px 16px;border-bottom:4px solid var(--ink);font-stretch:105%;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.panel>h3 .sp{flex:1}
.tabs{display:flex;gap:6px}
.tab{font:800 15px var(--disp);border:3px solid var(--ink);background:var(--white);padding:3px 10px;cursor:pointer;color:var(--ink)}
.tab.on{background:var(--ink);color:var(--white)}
.console{background:var(--ink);color:#E8ECF4;font-family:var(--mono);font-size:16px;font-weight:700;height:430px;overflow-y:auto;padding:12px 14px;line-height:1.45}
.console .ln{display:grid;grid-template-columns:78px 54px 1fr;gap:8px;padding:1px 0;animation:lnin .25s ease-out}
@keyframes lnin{from{background:rgba(255,255,255,.3)}}
.console .tm{color:#7C879B}
.console .tg{font-weight:800;text-align:center;color:var(--ink);padding:0 4px;height:22px;align-self:center;font-size:13px;line-height:22px}
.console .tg.factory{background:var(--fac)}.console .tg.home{background:var(--home)}.console .tg.patient{background:var(--pat)}
.console .hot{color:#FFE066}.console .err{color:#FF7B72}.console .good{color:#6CF2A6}
.console .empty{color:#7C879B;font-size:18px;padding:18px 4px}
.chips{display:flex;gap:8px;flex-wrap:wrap}
.chip{font:800 14px var(--mono);border:3px solid var(--ink);padding:2px 8px;background:#fff}
.chip.fac{background:var(--fac)}.chip.home{background:var(--home)}
.chip.off{background:#fff;color:var(--mute);border-style:dashed}
.cur{display:inline-block;width:10px;height:18px;background:#E8ECF4;vertical-align:-3px;animation:ledb 1s steps(2) infinite}

.integ{padding:16px}
.verdict{border:4px solid var(--ink);padding:14px 16px;display:flex;align-items:center;gap:16px;background:#D9F7E5}
.verdict .ic{width:56px;height:56px;border:4px solid var(--ink);background:var(--good);color:#fff;display:grid;place-items:center;font-size:34px;font-weight:900;flex:none}
.verdict h4{font-size:34px;font-weight:900;font-stretch:105%;line-height:1}
.verdict p{font-size:16px;font-weight:700;margin-top:4px}
body.alarm .verdict{background:var(--bad);color:#fff}
body.alarm .verdict .ic{background:#fff;color:var(--bad);animation:ledb .5s steps(2) infinite}
.facts{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:14px 0}
.fact{border:3px solid var(--ink);padding:8px 10px}
.fact b{font-size:34px;font-weight:900;display:block;line-height:1}
.fact span{font-size:14px;font-weight:800;color:var(--mute)}
.find{border:4px solid var(--bad);background:#FFF1F0;padding:12px 14px;margin-bottom:12px}
.find p{font-size:18px;font-weight:800;line-height:1.3;margin-bottom:8px}
.hash{font-family:var(--mono);font-size:14px;font-weight:700;word-break:break-all;margin-top:4px;line-height:1.5}
.hash em{font-style:normal;background:var(--bad);color:#fff}
.hash span{display:inline-block;width:92px;color:var(--mute)}
.sim{border-top:4px solid var(--ink);padding-top:14px;margin-top:6px}
.sim h4{font-size:20px;font-weight:900;margin-bottom:4px}
.sim p{font-size:15px;color:var(--mute);margin-bottom:10px;font-weight:700;line-height:1.35}
.arm{display:flex;align-items:center;gap:10px;font-size:17px;font-weight:800;margin-bottom:10px;cursor:pointer;user-select:none}
.arm input{width:24px;height:24px;accent-color:var(--bad)}
.sbtns{display:flex;flex-wrap:wrap;gap:12px}
.btn.atk{background:var(--bad);color:#fff}
.btn.rst{background:var(--good);color:#fff}
body.alarm #resetBtn{display:inline-block!important;border-color:#fff;box-shadow:4px 4px 0 var(--ink)}
.alog{background:var(--ink);color:#E8ECF4;font-family:var(--mono);font-size:15px;font-weight:700;padding:10px 12px;margin-top:12px;max-height:190px;overflow-y:auto;min-height:60px}
.alog .a{color:#FF7B72}.alog .m{color:#FFE066}.alog .s{color:#6CF2A6}
.alog div{padding:1px 0}

/* ---------- alarm ---------- */
.tape{position:fixed;left:0;right:0;top:0;height:0;overflow:hidden;z-index:50;background:repeating-linear-gradient(-45deg,var(--bad) 0 24px,#10131A 24px 48px);transition:height .25s}
body.alarm .tape{height:78px}
.tape div{position:absolute;inset:10px 0;background:var(--bad);color:#fff;display:flex;align-items:center;justify-content:center;font-size:40px;font-weight:900;font-stretch:112%;letter-spacing:.01em;border-top:4px solid var(--ink);border-bottom:4px solid var(--ink);white-space:nowrap;overflow:hidden}
body.alarm .wrap{padding-top:96px}
body.shake .wrap{animation:bigshake .5s}
@keyframes bigshake{20%{transform:translate(-8px,3px)}40%{transform:translate(8px,-3px)}60%{transform:translate(-5px,2px)}80%{transform:translate(5px,-2px)}}
body.alarm{background-color:#FFD9D6}
body.alarm::before{background:#FFD9D6;opacity:.9}

.hint{font-size:15px;font-weight:700;color:var(--mute);margin-top:6px}
@media(max-width:1100px){.low{grid-template-columns:1fr}.lane{grid-template-columns:1fr}.lhead{border-right:0;border-bottom:4px solid var(--ink)}.node{width:60px;height:60px;font-size:26px}.track::before,.fill{top:27px}.st .nm{font-size:15px}.st .sub{display:none}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div class="tape" aria-live="assertive"><div id="tapeText">TAMPERING DETECTED</div></div>
<div class="wrap">
  <div class="top">
    <div class="brand">Command Center<small>Privacy-preserving edge AI for secure IoT</small></div>
    <div class="sp"></div>
    <div class="leds" id="leds"></div>
    <button class="btn" id="snd" type="button">Sound off</button>
    <a class="btn" href="/">Dashboard</a>
  </div>

  <div id="lanes"></div>

  <div class="low">
    <section class="panel">
      <h3>Device console
        <span class="tabs" id="ctabs">
          <button class="tab on" data-f="all" type="button">All</button>
          <button class="tab" data-f="factory" type="button">Factory</button>
          <button class="tab" data-f="home" type="button">Home</button>
        </span>
        <span class="sp"></span>
        <span class="chips" id="devchips"></span>
      </h3>
      <div class="console" id="console"><div class="empty">Waiting for the devices. Lines appear here the moment they are printed.<span class="cur"></span></div></div>
    </section>

    <section class="panel">
      <h3>Evidence integrity</h3>
      <div class="integ">
        <div class="verdict" id="verdict">
          <div class="ic" id="vic">&#10003;</div>
          <div style="flex:1"><h4 id="vt">Evidence intact</h4><p id="vp">Checking every stored record...</p></div>
          <button class="btn rst" id="resetBtn" type="button" style="display:none">Reset alarm</button>
        </div>
        <div class="facts">
          <div class="fact"><b id="fBlocks">0</b><span>chain blocks verified</span></div>
          <div class="fact"><b id="fCloud">0</b><span>cloud files matched to ledger</span></div>
          <div class="fact"><b id="fAge">-</b><span>seconds since last check</span></div>
        </div>
        <div id="findings"></div>
        <div class="sim" id="sim">
          <h4>Attacker simulator</h4>
          <p>Edits the real stored evidence, exactly as an intruder with file access would. The monitor above must catch it and send a Telegram alert.</p>
          <label class="arm"><input type="checkbox" id="armed"> I am demonstrating. Allow the simulated attack.</label>
          <div class="sbtns">
            <button class="btn atk" data-a="chain" type="button" disabled>Hide an alert in the log</button>
            <button class="btn atk" data-a="chain_smart" type="button" disabled>Edit and re-seal the block</button>
            <button class="btn atk" data-a="cloud" type="button" disabled>Replace a cloud file</button>
            <button class="btn rst" data-a="restore" type="button" disabled>Restore the evidence</button>
          </div>
          <div class="alog" id="alog"></div>
        </div>
      </div>
    </section>
  </div>
</div>

<script>
(function(){
"use strict";
var STEPS=[["received","Received","IN"],["decrypt","Decrypt","KEY"],["chain","Chain","#"],["encrypt_cloud","Re-encrypt","LOCK"],["cloud","Cloud","UP"],["fabric","Ledger","LEDGER"],["alert","Alert","TG"]];
var LANES=[
 {id:"factory",title:"Factory",dev:"ESP32 + DHT11 humidity node",what:"High humidity"},
 {id:"home",title:"Home",dev:"ESP32-CAM person detector",what:"Person detected"},
 {id:"patient",title:"Patient",dev:"HW-627 pulse sensor",what:"Heart-rate anomaly"}
];
var resetErr="",runSeq=0,logSeq=0,sound=false,audio=null,alarm=false,filter="all";
var state={};  // lane -> {runs:[], sel:id}
LANES.forEach(function(l){state[l.id]={runs:[],sel:null,lastSeq:0,age:null,count:0}});

function $(i){return document.getElementById(i)}
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}

/* build lanes */
var lanesBox=$("lanes");
LANES.forEach(function(l){
  var s=el("section","lane waiting "+l.id);s.id="lane-"+l.id;
  var h=el("div","lhead");
  h.appendChild(el("h2","",l.title));
  h.appendChild(el("div","dev",l.dev));
  var p=el("div","pill");p.id="pill-"+l.id;p.appendChild(el("i"));p.appendChild(el("span","","Offline"));h.appendChild(p);
  var c=el("div","cnt");c.appendChild(el("b","","0"));c.lastChild.id="cnt-"+l.id;c.appendChild(document.createTextNode(l.what+" events"));h.appendChild(c);
  s.appendChild(h);
  var b=el("div","lbody");
  if(l.id==="factory"){
    var t=el("div","tele");t.id="tele";
    t.innerHTML='<div><div class="lbl">Humidity</div><div class="big" id="tHum">--<small>%</small></div></div><div><div class="lbl">Temperature</div><div class="big" id="tTemp">--<small>&deg;C</small></div></div><div class="bars"><div class="bar"><span style="text-align:left">Normal</span><div><i id="bN"></i></div><span id="bNv">--</span></div><div class="bar"><span style="text-align:left">High humidity</span><div><i id="bH" style="background:var(--bad)"></i></div><span id="bHv">--</span></div><div class="lbl" id="tInf">TinyML on the ESP32, waiting for a reading</div></div>';
    b.appendChild(t);
  }
  var m=el("div","meta");m.id="meta-"+l.id;b.appendChild(m);
  var tr=el("div","track");tr.id="track-"+l.id;
  var f=el("div","fill");f.id="fill-"+l.id;tr.appendChild(f);
  STEPS.forEach(function(st,i){
    var d=el("div","st");d.id="st-"+l.id+"-"+st[0];
    var n=el("div","node");d.appendChild(n);
    d.appendChild(el("div","nm",st[1]));
    var sb=el("div","sub","");sb.id="sub-"+l.id+"-"+st[0];d.appendChild(sb);
    tr.appendChild(d);
  });
  b.appendChild(tr);
  var sd=el("div","steps");sd.id="steps-"+l.id;b.appendChild(sd);
  var hi=el("div","hist");hi.id="hist-"+l.id;b.appendChild(hi);
  s.appendChild(b);lanesBox.appendChild(s);
});

/* ---------- rendering ---------- */
function fmtTime(iso){try{return new Date(iso).toLocaleTimeString([], {hour12:false})}catch(e){return ""}}
function render(laneId){
  var S=state[laneId],lane=$("lane-"+laneId);
  var run=null;
  for(var i=0;i<S.runs.length;i++){if(S.runs[i].id===S.sel)run=S.runs[i]}
  if(!run&&S.runs.length)run=S.runs[S.runs.length-1];
  var meta=$("meta-"+laneId),steps=$("steps-"+laneId),fill=$("fill-"+laneId);
  var info=null;LANES.forEach(function(l){if(l.id===laneId)info=l});
  STEPS.forEach(function(st){
    var d=$("st-"+laneId+"-"+st[0]);d.className="st";$("sub-"+laneId+"-"+st[0]).textContent="";
  });
  meta.textContent="";steps.textContent="";
  if(!run){
    lane.classList.add("waiting");lane.classList.remove("live");fill.style.width="0";
    var w=el("div","idle-msg","Armed and watching. The next "+info.what.toLowerCase()+" appears here the moment it happens.");
    meta.appendChild(w);return;
  }
  lane.classList.remove("waiting");
  var byKey={},last=-1,live=!run.done;
  run.steps.forEach(function(s){byKey[s.key]=s});
  STEPS.forEach(function(st,i){
    var s=byKey[st[0]];if(!s)return;
    var d=$("st-"+laneId+"-"+st[0]);d.className="st "+s.status;
    $("sub-"+laneId+"-"+st[0]).textContent=s.status==="running"?"working":(s.t_ms+" ms");
    if(s.status!=="running")last=i;else last=Math.max(last,i-0.5);
  });
  var frac=last<0?0:Math.min(1,(last+0.5)/6.5);
  fill.style.width="calc((100% - 14%) * "+Math.min(1,Math.max(0,last)/6)+")";
  lane.classList.toggle("live",live);
  [["Event",run.id],["From",run.src],["Time",fmtTime(run.started_utc)],["Reply",run.http||"..."],["Total",run.total_ms!=null?run.total_ms+" ms":"running"]].forEach(function(p){
    var sp=el("span","");sp.appendChild(el("b","",p[0]));sp.appendChild(document.createTextNode(" "+p[1]));meta.appendChild(sp)});
  if(run.ref){var sp=el("span","");sp.appendChild(el("b","","Ledger ID"));sp.appendChild(document.createTextNode(" "+run.ref));meta.appendChild(sp)}
  run.steps.forEach(function(s){
    var d=el("div",s.status==="fail"?"bad":"");
    var nm="";STEPS.forEach(function(st){if(st[0]===s.key)nm=st[1]});
    d.appendChild(el("b","",nm));d.appendChild(el("span","",s.detail||s.status));steps.appendChild(d);
  });
  /* history */
  var hi=$("hist-"+laneId);hi.textContent="";
  if(S.runs.length>1){
    hi.appendChild(el("span","","Earlier:"));
    S.runs.slice(-12).forEach(function(r){
      var fail=r.steps.some(function(s){return s.status==="fail"});
      var h=el("span","h"+(fail?" f":"")+(r.id===run.id?" sel":""));
      h.title=fmtTime(r.started_utc)+" "+r.id;
      h.addEventListener("click",function(){S.sel=r.id;render(laneId)});
      hi.appendChild(h);
    });
    var latest=el("span","btn","Latest");latest.style.cssText="padding:2px 8px;font-size:14px;box-shadow:2px 2px 0 var(--ink)";
    latest.addEventListener("click",function(){S.sel=null;render(laneId)});hi.appendChild(latest);
  }
}

function ingestRuns(runs){
  runs.forEach(function(r){
    var S=state[r.lane];if(!S)return;
    var found=false,prev=null;
    for(var i=0;i<S.runs.length;i++){if(S.runs[i].id===r.id){prev=S.runs[i];S.runs[i]=r;found=true}}
    if(!found){S.runs.push(r);if(S.runs.length>30)S.runs.shift();S.sel=null}
    /* sound + flash when a step finishes */
    var oldAlert=prev?stat(prev,"alert"):"";
    var newAlert=stat(r,"alert");
    if(newAlert==="ok"&&oldAlert!=="ok"){flash(r.lane);beep(880,.18)}
    if(stat(r,"fabric")==="ok"&&(!prev||stat(prev,"fabric")!=="ok")){flash(r.lane)}
    var fail=r.steps.some(function(s){return s.status==="fail"});
    if(fail&&(!prev||!prev.steps.some(function(s){return s.status==="fail"})))beep(180,.3);
    if(S.sel==null||S.sel===r.id)render(r.lane);else render(r.lane);
  });
}
function stat(r,k){for(var i=0;i<r.steps.length;i++)if(r.steps[i].key===k)return r.steps[i].status;return ""}
function flash(l){var e=$("lane-"+l);e.classList.remove("flash");void e.offsetWidth;e.classList.add("flash")}

/* ---------- console ---------- */
var cons=$("console"),consLines=[];
function addLogs(logs){
  if(!logs.length)return;
  if(!consLines.length)cons.textContent="";
  var atEnd=cons.scrollTop+cons.clientHeight>=cons.scrollHeight-40;
  logs.forEach(function(L){
    consLines.push(L);
    var d=new Date(L.t*1000),r=el("div","ln");r.dataset.lane=L.lane;
    r.appendChild(el("span","tm",d.toLocaleTimeString([], {hour12:false})));
    r.appendChild(el("span","tg "+L.lane,L.lane==="factory"?"FAC":L.lane==="home"?"CAM":"PUL"));
    var t=el("span","",L.text);
    if(/ANOMALY|HIGH_HUMIDITY|PERSON|INTRUSION|detected|alert/i.test(L.text)&&!/no person|not detected/i.test(L.text))t.className="hot";
    if(/fail|error|timeout|refused|invalid/i.test(L.text))t.className="err";
    if(/success|uploaded|sent|connected|ready|ok\b/i.test(L.text))t.className="good";
    r.appendChild(t);
    if(filter!=="all"&&filter!==L.lane)r.style.display="none";
    cons.appendChild(r);
  });
  while(cons.children.length>400)cons.removeChild(cons.firstChild);
  if(atEnd)cons.scrollTop=cons.scrollHeight;
}
$("ctabs").addEventListener("click",function(e){
  var b=e.target.closest(".tab");if(!b)return;filter=b.dataset.f;
  Array.prototype.forEach.call($("ctabs").children,function(x){x.classList.toggle("on",x===b)});
  Array.prototype.forEach.call(cons.children,function(r){if(r.dataset&&r.dataset.lane)r.style.display=(filter==="all"||filter===r.dataset.lane)?"":"none"});
  cons.scrollTop=cons.scrollHeight;
});

/* ---------- health + lanes + telemetry ---------- */
function setLeds(h){
  var names=[["flask","Server"],["chain","Hash chain"],["fabric","Fabric"],["cloud","Cloud"],["telegram","Telegram"]];
  var box=$("leds");box.textContent="";
  names.forEach(function(n){
    var x=h[n[0]]||{state:"idle"};
    var d=el("div","led "+(x.state==="ok"?"ok":x.state==="bad"?"bad":""));
    d.appendChild(el("i"));d.appendChild(document.createTextNode(n[1]));
    box.appendChild(d);
  });
}
function setLanes(l){
  var chips=$("devchips");chips.textContent="";
  [["factory","DHT11 console","fac"],["home","CAM console","home"]].forEach(function(c){
    var d=l[c[0]]||{};var ok=d.log_age!=null&&d.log_age<=12;
    var chip=el("span","chip "+(ok?c[2]:"off"),c[1]+": "+(d.log_age==null?"no signal":ok?"live":"silent "+d.log_age+" s"));
    chips.appendChild(chip);
  });
  LANES.forEach(function(L){
    var d=l[L.id]||{};var pill=$("pill-"+L.id);
    var live=!!d.online;
    pill.className="pill"+(live?" live":"");
    pill.lastChild.textContent=d.age==null?"No signal yet":live?"Online, "+d.age+" s ago":"Offline, silent for "+d.age+" s";
    if(!live&&state[L.id].runs.length){state[L.id].runs=[];state[L.id].sel=null;render(L.id)}
    if(!live&&L.id==="factory"&&$("tHum").firstChild.nodeValue!=="--"){
      $("tHum").firstChild.nodeValue="--";$("tTemp").firstChild.nodeValue="--";
      $("bN").style.width="0";$("bH").style.width="0";$("bNv").textContent="--";$("bHv").textContent="--";
      $("tInf").textContent="Device offline. Waiting for the next reading";
    }
    var c=$("cnt-"+L.id);if(c.textContent!==String(d.count))c.textContent=d.count||0;
  });
}
function setTele(t){
  if(!t||t.humidity==null)return;
  $("tHum").firstChild.nodeValue=t.humidity.toFixed(1);
  if(t.temperature!=null)$("tTemp").firstChild.nodeValue=t.temperature.toFixed(1);
  if(t.score_normal!=null){
    $("bN").style.width=(t.score_normal*100)+"%";$("bNv").textContent=Math.round(t.score_normal*100)+"%";
    $("bH").style.width=(t.score_high*100)+"%";$("bHv").textContent=Math.round(t.score_high*100)+"%";
  }
  $("tInf").textContent="TinyML on the ESP32: "+(t.prediction||"-")+(t.inference_ms!=null?", decided in "+t.inference_ms+" ms":"");
}

/* ---------- integrity ---------- */
function diffHash(a,b){
  var out=document.createDocumentFragment();
  for(var i=0;i<Math.min(a.length,64);i++){
    var ch=a[i];if(b&&b[i]!==ch){var m=el("em","",ch);out.appendChild(m)}else out.appendChild(document.createTextNode(ch));
  }
  return out;
}
function setIntegrity(I){
  var bad=I.state==="compromised";
  if(bad!==alarm){
    alarm=bad;document.body.classList.toggle("alarm",bad);
    $("vt").textContent=bad?"Tampering detected":"Evidence intact";
    $("vic").textContent=bad?"!":"✓";
    if(bad){document.body.classList.add("shake");setTimeout(function(){document.body.classList.remove("shake")},600);siren()}
  }
  $("vp").textContent=bad?(resetErr||"Stored data no longer matches its fingerprints. Alert sent to Telegram."):"Every record matches its fingerprint and the ledger.";
  $("fBlocks").textContent=I.chain_blocks;$("fCloud").textContent=I.cloud_checked;
  $("fAge").textContent=I.checked_age==null?"-":I.checked_age;
  var f=$("findings");f.textContent="";
  (I.findings||[]).forEach(function(x){
    var b=el("div","find");b.appendChild(el("p","",x.summary));
    var e=el("div","hash");e.appendChild(el("span","","Should be"));e.appendChild(document.createTextNode(x.expected));b.appendChild(e);
    var g=el("div","hash");g.appendChild(el("span","","Found"));g.appendChild(diffHash(x.found,x.expected));b.appendChild(g);
    f.appendChild(b);
  });
  var log=$("alog");log.textContent="";
  (I.attack_log||[]).forEach(function(a){
    var d=el("div",a.actor==="ATTACKER"?"a":a.actor==="MONITOR"?"m":"s");
    d.textContent=new Date(a.t*1000).toLocaleTimeString([], {hour12:false})+"  "+a.actor+": "+a.text;log.appendChild(d)});
  log.scrollTop=log.scrollHeight;
  var armed=$("armed").checked&&!I.attack_busy&&I.attack_enabled;
  Array.prototype.forEach.call(document.querySelectorAll("[data-a]"),function(b){
    var rst=b.dataset.a==="restore";
    b.disabled=rst?(I.attack_busy||(!I.has_tamper&&!bad)):!armed});
  $("resetBtn").disabled=!!I.attack_busy;
  $("sim").style.display=I.attack_enabled?"":"none";
}
$("armed").addEventListener("change",function(){poll()});
function sendAttack(kind){
  var note=function(t){var d=el("div","s",new Date().toLocaleTimeString([], {hour12:false})+"  YOU: "+t);$("alog").appendChild(d);$("alog").scrollTop=$("alog").scrollHeight};
  return fetch("/api/dashboard-info",{credentials:"same-origin",cache:"no-store"})
   .then(function(r){if(r.status===401){location.href="/login";throw 0}return r.json()})
   .then(function(t){
     document.querySelector("meta[name=csrf]").content=t.csrf_token;
     return fetch("/api/attack/"+kind,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRFToken":t.csrf_token},body:JSON.stringify({confirm:"ATTACK"})});
   })
   .then(function(r){return r.json().catch(function(){return {}}).then(function(j){
     if(!r.ok){note("The request was refused: "+(j.error||("HTTP "+r.status)));resetErr="Reset failed: "+(j.error||("HTTP "+r.status));}else{resetErr=""}
     poll();
   })})
   .catch(function(e){if(e!==0)note("Could not reach the server.")});
}
$("resetBtn").addEventListener("click",function(){var b=this;b.textContent="Resetting...";sendAttack("restore").then(function(){setTimeout(function(){b.textContent="Reset alarm"},3000)})});
document.querySelector(".sbtns").addEventListener("click",function(e){
  var b=e.target.closest("[data-a]");if(!b||b.disabled)return;
  fetch("/api/attack/"+b.dataset.a,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRFToken":document.querySelector("meta[name=csrf]").content},body:JSON.stringify({confirm:"ATTACK"})}).then(function(){poll()});
});

/* ---------- sound ---------- */
function ctx(){if(!audio){try{audio=new (window.AudioContext||window.webkitAudioContext)()}catch(e){}}return audio}
function beep(f,d){if(!sound)return;var a=ctx();if(!a)return;var o=a.createOscillator(),g=a.createGain();o.frequency.value=f;o.type="square";g.gain.value=.06;o.connect(g);g.connect(a.destination);o.start();o.stop(a.currentTime+d)}
function siren(){beep(520,.25);setTimeout(function(){beep(380,.25)},280);setTimeout(function(){beep(520,.25)},560)}
$("snd").addEventListener("click",function(){sound=!sound;this.textContent=sound?"Sound on":"Sound off";if(sound){ctx();if(audio&&audio.resume)audio.resume();beep(660,.12)}});

/* ---------- polling ---------- */
var busy=false,first=true;
function poll(){
  if(busy)return;busy=true;
  fetch("/api/live?run_since="+runSeq+"&log_since="+logSeq,{credentials:"same-origin",cache:"no-store"})
  .then(function(r){if(r.status===401||r.redirected){location.href="/login";throw 0}return r.json()})
  .then(function(d){
    if(first&&d.runs.length){d.runs.sort(function(a,b){return a.seq-b.seq})}
    runSeq=d.run_seq;logSeq=d.log_seq;
    ingestRuns(d.runs);addLogs(d.logs);setLeds(d.health);setLanes(d.lanes);setTele(d.telemetry);setIntegrity(d.integrity);
    if(first){first=false;LANES.forEach(function(l){render(l.id)})}
  }).catch(function(){}).then(function(){busy=false});
}
LANES.forEach(function(l){render(l.id)});
poll();setInterval(poll,400);
})();
</script>
</body>
</html>
"""
