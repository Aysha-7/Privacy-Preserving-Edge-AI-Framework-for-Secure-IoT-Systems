# ==================================================
# STAGE 1: AUTHORISED VAULT
# ==================================================
# Sensitive device details (who / where / which department) are added to
# each event BEFORE it is encrypted for Cloudinary, so the cloud and the
# Fabric ledger never hold them in readable form. Only a signed-in
# dashboard user who also unlocks a role password can fetch the record,
# verify its hash against Fabric, and decrypt it.

VAULT_DIR = Path(os.environ.get("LOCALAPPDATA", str(BASE_DIR))) / "iot_fabric"
VAULT_INDEX_FILE = BASE_DIR / "vault_index.jsonl"
VAULT_AUDIT_FILE = BASE_DIR / "vault_audit.jsonl"
PROFILES_FILE = BASE_DIR / "device_profiles.json"
VAULT_LOCK = threading.Lock()
VAULT_SESSION_SECONDS = 300

VAULT_ROLES = {
    "factory_manager": {
        "label": "Factory manager",
        "domain": "factory",
        "sees": "Humidity sensor details, original readings",
    },
    "doctor": {
        "label": "Doctor",
        "domain": "patient",
        "sees": "Patient identity, heart-rate alerts and waveform",
    },
    "homeowner": {
        "label": "Homeowner",
        "domain": "home",
        "sees": "Room and owner details, the original camera image",
    },
}

# Made-up demonstration data. Edit device_profiles.json to change it.
DEFAULT_PROFILES = {
    "factory": {
        "sensor_id": "HUM-DHT11-A07",
        "sensor_model": "DHT11 + ESP32 (TinyML humidity classifier)",
        "plant": "Riverside Textile Mill (demo)",
        "department": "Dyeing and Finishing",
        "location": "Bay 3, Rack C, 2.4 m above floor",
        "floor": "Ground floor, East wing",
        "responsible_manager": "Mr. R. Karthik (demo)",
        "safe_humidity_limit": "70 %",
        "installed_on": "2026-08-14",
    },
    "patient": {
        "patient_id": "PT-20418",
        "patient_name": "Meera Nair (demo)",
        "age": 54,
        "ward": "Cardiology Ward 2",
        "bed": "Bed 14",
        "attending_doctor": "Dr. S. Iyer (demo)",
        "monitor": "Wrist pulse monitor (HW-627)",
        "normal_bpm_range": "60 to 100",
    },
    "home": {
        "owner": "Ameera",
        "room": "Living room",
        "camera_position": "Above the front door, facing the hallway",
        "address": "12, Lakeview Residency, Chennai (demo address)",
        "emergency_contact": "Family member (demo)",
        "security_mode": "Armed",
    },
}


def get_profile(domain):
    try:
        if PROFILES_FILE.exists():
            data = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
            if isinstance(data.get(domain), dict):
                return data[domain]
        else:
            PROFILES_FILE.write_text(
                json.dumps(DEFAULT_PROFILES, indent=2),
                encoding="utf-8",
            )
    except (OSError, ValueError):
        app.logger.exception("Could not read device_profiles.json")

    return DEFAULT_PROFILES.get(domain, {})


def classify_domain(event):
    """Decide which application an event belongs to from its content."""

    if not isinstance(event, dict):
        return None

    if "humidity_percent" in event:
        return "factory"

    if "bpm" in event or "heart_rate_bpm" in event:
        return "patient"

    if str(event.get("event_id", "")).startswith("cam_"):
        return "home"

    return None


def vault_audit(role, action, event_id="", result="ok"):
    entry = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "role": role or "none",
        "action": action,
        "event_id": event_id,
        "result": result,
        "client": request.remote_addr if request else "",
    }

    try:
        with VAULT_LOCK:
            with VAULT_AUDIT_FILE.open("a", encoding="utf-8") as file:
                file.write(canonical_json(entry) + "\n")
    except OSError:
        app.logger.exception("Could not write vault audit entry")


def vault_register(domain, kind, cloud_public_id, timestamp, ref_id=None):
    """Remember which cloud object belongs to which application."""

    entry = {
        "event_id": cloud_public_id.rsplit("/", 1)[-1],
        "domain": domain,
        "kind": kind,
        "timestamp_utc": timestamp,
        "cloud_public_id": cloud_public_id,
        "ref_id": ref_id,
    }

    try:
        with VAULT_LOCK:
            with VAULT_INDEX_FILE.open("a", encoding="utf-8") as file:
                file.write(canonical_json(entry) + "\n")
    except OSError:
        app.logger.exception("Could not write vault index entry")


def vault_read_index():
    entries = []

    if not VAULT_INDEX_FILE.exists():
        return entries

    try:
        with VAULT_LOCK:
            lines = VAULT_INDEX_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return entries

    for line in lines:
        try:
            item = json.loads(line)
            if isinstance(item, dict) and item.get("event_id"):
                entries.append(item)
        except ValueError:
            continue

    return entries


def vault_image_links():
    """Map image event id -> camera event id (from image_events.jsonl)."""

    links = {}
    path = BASE_DIR / "image_events.jsonl"

    if not path.exists():
        return links

    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
                links[item["event_id"]] = item.get(
                    "related_camera_event_id"
                )
            except (ValueError, KeyError):
                continue
    except OSError:
        pass

    return links


# ---- Wrap the existing upload so the profile is encrypted with the event

_original_upload_encrypted_event_to_cloud = upload_encrypted_event_to_cloud


def upload_encrypted_event_to_cloud(event):  # noqa: F811
    domain = classify_domain(event)
    payload = event

    if domain:
        payload = dict(event)
        payload["profile_domain"] = domain
        payload["profile"] = get_profile(domain)

    result = _original_upload_encrypted_event_to_cloud(payload)

    if domain and result.get("public_id"):
        vault_register(
            domain=domain,
            kind="event",
            cloud_public_id=result["public_id"],
            timestamp=event.get("timestamp_utc"),
            ref_id=event.get("event_id"),
        )

    return result


# ---- Wrap the Fabric call so encrypted camera images are indexed too

_original_record_event_on_fabric = record_event_on_fabric


def record_event_on_fabric(*args, **kwargs):  # noqa: F811
    event_id = kwargs.get("event_id") or (args[0] if args else "")
    reference = kwargs.get("cloud_reference") or (
        args[3] if len(args) > 3 else ""
    )
    timestamp = kwargs.get("timestamp") or (
        args[1] if len(args) > 1 else ""
    )

    if str(event_id).startswith("image_") and reference:
        vault_register(
            domain="home",
            kind="image",
            cloud_public_id=reference,
            timestamp=timestamp,
        )

    return _original_record_event_on_fabric(*args, **kwargs)


# ---- Role passwords (hashes only, stored outside the project folder)

def vault_role_hash(role):
    path = VAULT_DIR / f"vault_{role}.hash"

    try:
        value = path.read_text(encoding="utf-8").strip()
        return value or None
    except OSError:
        return None


def vault_current_role():
    role = session.get("vault_role")
    until = session.get("vault_until", 0)

    if role in VAULT_ROLES and time.time() < until:
        return role

    session.pop("vault_role", None)
    session.pop("vault_until", None)
    return None


def vault_error(message, status):
    return jsonify({"error": message}), status


# ---- Fetch, verify and decrypt one cloud object

class VaultError(Exception):
    def __init__(self, message, status=502, steps=None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.steps = steps or []


def vault_fetch_verified(event_id):
    """
    1. Read the trusted hash and cloud reference from Fabric.
    2. Download the encrypted object from Cloudinary.
    3. Compare its SHA-256 with the ledger.
    4. Decrypt with AES-256-GCM (this also authenticates it).
    Returns (plaintext_bytes, envelope_format, steps).
    """

    steps = []

    if not FABRIC_GATEWAY_TOKEN:
        raise VaultError("Fabric gateway is not configured.", 503, steps)

    try:
        ledger_response = requests.get(
            FABRIC_GATEWAY_URL.rstrip("/") + "/" + event_id,
            headers={"Authorization": f"Bearer {FABRIC_GATEWAY_TOKEN}"},
            timeout=15,
        )
        ledger_response.raise_for_status()
        ledger_data = ledger_response.json()
    except Exception:
        steps.append({"name": "Ledger record", "ok": False,
                      "detail": "Fabric did not answer."})
        raise VaultError("Could not read the Fabric ledger.", 502, steps)

    ledger_event = ledger_data.get("event", {}) if isinstance(
        ledger_data, dict) else {}

    expected_hash = str(ledger_event.get("encryptedFileHash", "")).lower()
    reference = str(ledger_event.get("cloudReference", ""))

    if (
        ledger_data.get("status") != "found"
        or ledger_event.get("eventId") != event_id
        or len(expected_hash) != 64
        or any(c not in "0123456789abcdef" for c in expected_hash)
        or not reference.startswith("encrypted_iot_events/")
    ):
        steps.append({"name": "Ledger record", "ok": False,
                      "detail": "No valid record for this event on Fabric."})
        raise VaultError("Event is not on the Fabric ledger.", 404, steps)

    steps.append({
        "name": "Ledger record",
        "ok": True,
        "detail": "Found on Hyperledger Fabric",
        "ledger_time": ledger_event.get("timestamp"),
        "ledger_hash": expected_hash,
    })

    try:
        asset = cloudinary.api.resource(reference, resource_type="raw")
        download_url = asset.get("secure_url")

        if not download_url:
            raise RuntimeError("no url")

        limit = 10 * 1024 * 1024
        chunks = []
        total = 0

        with requests.get(download_url, stream=True,
                          timeout=(10, 30)) as response:
            response.raise_for_status()

            for chunk in response.iter_content(chunk_size=64 * 1024):
                total += len(chunk)
                if total > limit:
                    raise RuntimeError("too large")
                chunks.append(chunk)

        encrypted_bytes = b"".join(chunks)

    except Exception:
        steps.append({"name": "Encrypted file", "ok": False,
                      "detail": "Could not download from Cloudinary."})
        raise VaultError("Could not download the encrypted file.", 502, steps)

    actual_hash = hashlib.sha256(encrypted_bytes).hexdigest()

    steps.append({
        "name": "Encrypted file",
        "ok": True,
        "detail": f"Downloaded {len(encrypted_bytes)} bytes (ciphertext)",
    })

    if not secrets.compare_digest(actual_hash, expected_hash):
        steps.append({"name": "Integrity check", "ok": False,
                      "detail": "SHA-256 does not match the ledger."})
        raise VaultError("Integrity verification failed.", 409, steps)

    steps.append({
        "name": "Integrity check",
        "ok": True,
        "detail": "SHA-256 of the cloud file matches the ledger",
        "cloud_hash": actual_hash,
    })

    try:
        envelope = json.loads(encrypted_bytes.decode("utf-8"))
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        blob = base64.b64decode(envelope["ciphertext_and_tag"],
                                validate=True)

        if len(nonce) != 12:
            raise ValueError("nonce")

        plaintext = CLOUD_AES.decrypt(nonce, blob, None)
        envelope_format = envelope.get("format", "")

    except Exception:
        steps.append({"name": "AES-256-GCM decrypt", "ok": False,
                      "detail": "Authentication tag check failed."})
        raise VaultError("Decryption failed.", 400, steps)

    steps.append({
        "name": "AES-256-GCM decrypt",
        "ok": True,
        "detail": "Authentication tag valid; data decrypted in memory",
    })

    return plaintext, envelope_format, steps


def vault_authorised_entry(event_id, role):
    """Return the index entry only if it belongs to this role's domain."""

    domain = VAULT_ROLES[role]["domain"]

    for entry in vault_read_index():
        if entry.get("event_id") == event_id and entry.get("domain") == domain:
            return entry

    return None


# ---- Routes

@app.get("/vault")
@dashboard_login_required
def vault_page():
    return Response(
        VAULT_PAGE,
        mimetype="text/html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/vault/status")
@dashboard_login_required
def vault_status():
    role = vault_current_role()

    return jsonify({
        "unlocked": bool(role),
        "role": role,
        "label": VAULT_ROLES[role]["label"] if role else None,
        "seconds_left": max(
            0, int(session.get("vault_until", 0) - time.time())
        ) if role else 0,
        "roles": [
            {
                "key": key,
                "label": value["label"],
                "sees": value["sees"],
                "configured": vault_role_hash(key) is not None,
            }
            for key, value in VAULT_ROLES.items()
        ],
    })


@app.post("/api/vault/unlock")
@dashboard_login_required
@limiter.limit("6 per minute")
def vault_unlock():
    body = request.get_json(silent=True) or {}
    role = body.get("role")
    password = body.get("password", "")

    if role not in VAULT_ROLES or not isinstance(password, str):
        return vault_error("Choose a valid role.", 400)

    stored = vault_role_hash(role)

    if not stored:
        return vault_error(
            "This role has no password set yet. "
            "Run set_vault_passwords.py first.", 503)

    if not check_password_hash(stored, password):
        vault_audit(role, "unlock", result="wrong password")
        return vault_error("Wrong password for this role.", 403)

    session["vault_role"] = role
    session["vault_until"] = time.time() + VAULT_SESSION_SECONDS
    vault_audit(role, "unlock")

    return jsonify({"unlocked": True, "role": role})


@app.post("/api/vault/lock")
@dashboard_login_required
def vault_lock():
    vault_audit(session.get("vault_role"), "lock")
    session.pop("vault_role", None)
    session.pop("vault_until", None)
    return jsonify({"unlocked": False})


@app.get("/api/vault/records")
@dashboard_login_required
def vault_records():
    role = vault_current_role()

    if not role:
        return vault_error("Authorised area is locked.", 401)

    domain = VAULT_ROLES[role]["domain"]
    links = vault_image_links()
    rows = []

    for entry in vault_read_index():
        if entry.get("domain") != domain:
            continue

        rows.append({
            "event_id": entry["event_id"],
            "kind": entry.get("kind", "event"),
            "timestamp_utc": entry.get("timestamp_utc"),
            "related": links.get(entry["event_id"]) or entry.get("ref_id"),
        })

    rows.sort(key=lambda r: r.get("timestamp_utc") or "", reverse=True)

    return jsonify({"role": role, "records": rows[:50]})


@app.get("/api/vault/event/<event_id>")
@dashboard_login_required
def vault_event(event_id):
    role = vault_current_role()

    if not role:
        return vault_error("Authorised area is locked.", 401)

    entry = vault_authorised_entry(event_id, role)

    if not entry:
        vault_audit(role, "decrypt", event_id, "denied")
        return vault_error("Your role cannot open this record.", 403)

    try:
        plaintext, envelope_format, steps = vault_fetch_verified(event_id)
    except VaultError as exc:
        vault_audit(role, "decrypt", event_id, exc.message)
        return jsonify({"error": exc.message, "steps": exc.steps}), exc.status

    vault_audit(role, "decrypt", event_id)

    if envelope_format == "AES-256-GCM-IMAGE":
        return jsonify({
            "kind": "image",
            "steps": steps,
            "image_url": f"/api/vault/image/{event_id}",
            "reading": {},
            "profile": {},
            "related": vault_image_links().get(event_id),
        })

    try:
        document = json.loads(plaintext.decode("utf-8"))
    except ValueError:
        return vault_error("Decrypted data is not valid JSON.", 415)

    profile = document.pop("profile", {})
    document.pop("profile_domain", None)

    linked_images = []

    if entry.get("ref_id"):
        for image_id, camera_id in vault_image_links().items():
            if camera_id == entry["ref_id"] and vault_authorised_entry(
                image_id, role
            ):
                linked_images.append(image_id)

    return jsonify({
        "kind": "event",
        "steps": steps,
        "reading": document,
        "profile": profile,
        "linked_images": linked_images,
    })


@app.get("/api/vault/image/<event_id>")
@dashboard_login_required
def vault_image(event_id):
    role = vault_current_role()

    if not role:
        return vault_error("Authorised area is locked.", 401)

    entry = vault_authorised_entry(event_id, role)

    if not entry or entry.get("kind") != "image":
        return vault_error("Your role cannot open this image.", 403)

    try:
        plaintext, envelope_format, _steps = vault_fetch_verified(event_id)
    except VaultError as exc:
        return vault_error(exc.message, exc.status)

    if (envelope_format != "AES-256-GCM-IMAGE"
            or not plaintext.startswith(b"\xff\xd8\xff")):
        return vault_error("Not a valid encrypted image.", 415)

    vault_audit(role, "view image", event_id)

    return Response(
        plaintext,
        mimetype="image/jpeg",
        headers={
            "Cache-Control": "no-store, private",
            "X-Content-Type-Options": "nosniff",
        },
    )


VAULT_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorised Personnel Only</title>
<style>
:root{
  --bg:#08111f;--panel:#0e1a2e;--panel2:#12223a;--line:#1f3250;
  --text:#e6eefb;--muted:#8aa0c0;--cyan:#52d6d0;--green:#4ade80;
  --red:#ff6b6b;--amber:#fbbf24;--violet:#a78bfa;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 70% -10%,#12315a55,transparent),var(--bg);
  color:var(--text);font-family:system-ui,Segoe UI,Roboto,sans-serif;min-height:100vh}
header{display:flex;justify-content:space-between;align-items:center;
  padding:14px 20px;border-bottom:1px solid var(--line);gap:12px;flex-wrap:wrap}
a.back{color:var(--cyan);text-decoration:none;font-size:14px}
h1{font-size:18px;margin:0;letter-spacing:.04em}
.warn{color:var(--amber);font-size:12px;letter-spacing:.14em;text-transform:uppercase}
main{max-width:1100px;margin:0 auto;padding:22px 16px 60px}
.hidden{display:none!important}
.roles{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:18px 0}
.role{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;
  cursor:pointer;transition:transform .2s,border-color .2s,box-shadow .2s;text-align:left;color:inherit;font:inherit}
.role:hover{transform:translateY(-3px);border-color:var(--cyan)}
.role.sel{border-color:var(--cyan);box-shadow:0 0 0 1px var(--cyan),0 10px 30px #52d6d022}
.role .ico{font-size:28px}
.role b{display:block;margin:8px 0 4px}
.role span{color:var(--muted);font-size:13px}
.role .off{color:var(--red);font-size:12px;margin-top:6px;display:block}
.unlock{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;
  display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input[type=password]{flex:1;min-width:200px;background:var(--bg);border:1px solid var(--line);
  color:var(--text);padding:12px 14px;border-radius:10px;font-size:15px}
button.primary{background:var(--cyan);color:#04201f;border:0;padding:12px 20px;border-radius:10px;
  font-weight:700;cursor:pointer}
button.ghost{background:transparent;color:var(--text);border:1px solid var(--line);
  padding:8px 14px;border-radius:10px;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
.err{color:var(--red);font-size:14px;margin-top:10px;min-height:20px}
.bar{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.pill{background:var(--panel2);border:1px solid var(--line);border-radius:99px;padding:6px 12px;font-size:13px}
.pill b{color:var(--cyan)}
.cols{display:grid;grid-template-columns:320px 1fr;gap:16px}
@media(max-width:820px){.cols{grid-template-columns:1fr}}
.list,.detail{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px}
.rec{display:block;width:100%;text-align:left;background:var(--panel2);border:1px solid transparent;
  color:inherit;font:inherit;border-radius:10px;padding:10px 12px;margin-bottom:8px;cursor:pointer}
.rec:hover{border-color:var(--cyan)}
.rec.sel{border-color:var(--cyan)}
.rec small{display:block;color:var(--muted);margin-top:3px;font-family:ui-monospace,Consolas,monospace;font-size:11px}
.tag{font-size:11px;padding:2px 8px;border-radius:99px;border:1px solid var(--line);color:var(--violet);margin-left:6px}
.empty{color:var(--muted);padding:30px 10px;text-align:center}
.step{display:flex;gap:10px;align-items:flex-start;padding:8px 0;opacity:0;transform:translateY(6px);
  animation:in .4s forwards}
@keyframes in{to{opacity:1;transform:none}}
.step .dot{width:22px;height:22px;border-radius:50%;display:grid;place-items:center;font-size:13px;
  flex:none;background:#4ade8022;color:var(--green);border:1px solid var(--green)}
.step.bad .dot{background:#ff6b6b22;color:var(--red);border-color:var(--red)}
.step b{font-size:14px}.step span{display:block;color:var(--muted);font-size:12px;
  font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
.tile{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:12px}
.tile small{color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-size:11px}
.tile .v{font-size:28px;font-weight:700;color:var(--cyan);font-family:ui-monospace,Consolas,monospace}
h3{margin:18px 0 8px;font-size:13px;color:var(--muted);letter-spacing:.12em;text-transform:uppercase}
table{width:100%;border-collapse:collapse}
td{padding:8px 6px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:top}
td:first-child{color:var(--muted);width:42%}
td.v{font-family:ui-monospace,Consolas,monospace}
img.shot{max-width:100%;border-radius:10px;border:1px solid var(--line);image-rendering:pixelated;
  width:100%;max-width:480px;background:#000}
.note{color:var(--muted);font-size:12px;margin-top:14px}
@media(prefers-reduced-motion:reduce){*{animation-duration:.01s!important;transition:none!important}}
</style>
</head>
<body>
<header>
  <div><a class="back" href="/">&larr; Dashboard</a></div>
  <div style="text-align:center"><div class="warn">Authorised personnel only</div>
    <h1>Encrypted Vault</h1></div>
  <div id="timer" class="pill hidden"></div>
</header>
<main>
  <section id="lockView">
    <p style="color:var(--muted)">Sensitive details are stored only as AES-256-GCM ciphertext in the cloud.
      Choose your role and enter its password to fetch, verify and decrypt them.</p>
    <div class="roles" id="roles"></div>
    <div class="unlock">
      <input id="pw" type="password" placeholder="Role password" autocomplete="off">
      <button class="primary" id="unlockBtn">Unlock</button>
    </div>
    <div class="err" id="err"></div>
  </section>

  <section id="openView" class="hidden">
    <div class="bar">
      <div class="pill">Signed in as <b id="roleName"></b></div>
      <button class="ghost" id="lockBtn">Lock now</button>
    </div>
    <div class="cols">
      <div class="list"><div id="records"></div></div>
      <div class="detail" id="detail"><div class="empty">Select a record to verify and decrypt it.</div></div>
    </div>
  </section>
</main>

<script>
const $ = id => document.getElementById(id);
const ICONS = {factory_manager:"\u{1F3ED}", doctor:"\u{1FA7A}", homeowner:"\u{1F3E0}"};
let csrf = "", chosen = null, tick = null, selected = null;

function h(tag, props, ...kids){
  const e = document.createElement(tag);
  Object.assign(e, props || {});
  kids.flat().forEach(k => e.append(k));
  return e;
}
const nice = k => k.replace(/_/g," ").replace(/^./, c => c.toUpperCase());
const fmtTime = t => t ? new Date(t).toLocaleString() : "unknown";

async function api(url, opts){
  const r = await fetch(url, {credentials:"same-origin", ...opts});
  let data = {};
  try { data = await r.json(); } catch(e){}
  if(!r.ok){ const e = new Error(data.error || ("HTTP " + r.status)); e.data = data; e.status = r.status; throw e; }
  return data;
}

async function loadCsrf(){ csrf = (await api("/api/dashboard-info")).csrf_token; }

function scramble(el, finalText){
  const chars = "0123456789abcdef#%@";
  if(matchMedia("(prefers-reduced-motion: reduce)").matches){ el.textContent = finalText; return; }
  let n = 0;
  const id = setInterval(() => {
    n++;
    el.textContent = finalText.split("").map((c,i) =>
      (c === " " || i < n/1.2) ? c : chars[Math.floor(Math.random()*chars.length)]).join("");
    if(n > finalText.length*1.2 + 4){ clearInterval(id); el.textContent = finalText; }
  }, 30);
}

function renderRoles(roles){
  const box = $("roles"); box.innerHTML = "";
  roles.forEach(r => {
    const b = h("button", {className:"role", type:"button"},
      h("div", {className:"ico", textContent:ICONS[r.key] || "\u{1F512}"}),
      h("b", {textContent:r.label}),
      h("span", {textContent:r.sees}));
    if(!r.configured) b.append(h("span", {className:"off", textContent:"No password set yet"}));
    b.onclick = () => { chosen = r.key;
      [...box.children].forEach(c => c.classList.remove("sel")); b.classList.add("sel"); $("pw").focus(); };
    box.append(b);
  });
}

function showLocked(roles){
  $("lockView").classList.remove("hidden");
  $("openView").classList.add("hidden");
  $("timer").classList.add("hidden");
  clearInterval(tick);
  if(roles) renderRoles(roles);
}

function showOpen(status){
  $("lockView").classList.add("hidden");
  $("openView").classList.remove("hidden");
  $("roleName").textContent = status.label;
  $("timer").classList.remove("hidden");
  let left = status.seconds_left;
  clearInterval(tick);
  const draw = () => {
    const m = Math.floor(left/60), s = String(left%60).padStart(2,"0");
    $("timer").textContent = "\u{1F513} auto-locks in " + m + ":" + s;
  };
  draw();
  tick = setInterval(() => { left--; if(left <= 0){ clearInterval(tick); init(); } else draw(); }, 1000);
  loadRecords();
}

async function loadRecords(){
  const box = $("records"); box.innerHTML = "";
  let data;
  try { data = await api("/api/vault/records"); } catch(e){ box.append(h("div",{className:"empty",textContent:e.message})); return; }
  if(!data.records.length){
    box.append(h("div",{className:"empty",textContent:"No protected records yet for this role."})); return; }
  data.records.forEach(r => {
    const b = h("button", {className:"rec", type:"button"},
      h("div", {}, h("b",{textContent:fmtTime(r.timestamp_utc)}),
        h("span",{className:"tag",textContent:r.kind === "image" ? "encrypted image" : "event"})),
      h("small",{textContent:r.event_id}));
    b.onclick = () => { selected = r.event_id;
      [...box.children].forEach(c => c.classList.remove("sel")); b.classList.add("sel"); openRecord(r); };
    box.append(b);
  });
}

function table(obj){
  const t = h("table");
  Object.entries(obj).forEach(([k,v]) => {
    const td = h("td",{className:"v"});
    t.append(h("tr",{}, h("td",{textContent:nice(k)}), td));
    scramble(td, typeof v === "object" ? JSON.stringify(v) : String(v));
  });
  return t;
}

async function openRecord(r){
  const d = $("detail");
  d.innerHTML = "";
  d.append(h("div",{className:"empty",textContent:"Fetching from Fabric and Cloudinary…"}));
  let data;
  try { data = await api("/api/vault/event/" + encodeURIComponent(r.event_id)); }
  catch(e){
    d.innerHTML = "";
    (e.data && e.data.steps || []).forEach((s,i) => d.append(stepEl(s,i)));
    d.append(h("div",{className:"err",textContent:e.message}));
    return;
  }
  d.innerHTML = "";
  d.append(h("h3",{textContent:"Verification"}));
  data.steps.forEach((s,i) => d.append(stepEl(s,i)));
  const delay = data.steps.length*350 + 200;

  setTimeout(async () => {
    if(selected !== r.event_id) return;
    if(data.kind === "image"){
      d.append(h("h3",{textContent:"Decrypted image"}));
      try{
        const resp = await fetch(data.image_url, {credentials:"same-origin"});
        if(!resp.ok) throw new Error("image");
        const img = h("img",{className:"shot",alt:"Decrypted camera image"});
        img.src = URL.createObjectURL(await resp.blob());
        d.append(img);
      }catch(e){ d.append(h("div",{className:"err",textContent:"Could not decrypt the image."})); }
      return;
    }
    const rd = data.reading || {};
    const tiles = h("div",{className:"tiles"});
    [["humidity_percent","Humidity","%"],["temperature_c","Temperature","°C"],
     ["bpm","Heart rate","BPM"],["person_confidence","Person confidence",""],
     ["motion_score","Motion score",""]].forEach(([k,label,unit]) => {
      if(rd[k] === undefined) return;
      const v = h("div",{className:"v"});
      tiles.append(h("div",{className:"tile"}, h("small",{textContent:label}), v));
      scramble(v, (typeof rd[k] === "number" ? (Number.isInteger(rd[k]) ? rd[k] : rd[k].toFixed(k==="person_confidence"?3:1)) : rd[k]) + (unit ? " " + unit : ""));
    });
    d.append(h("h3",{textContent:"Original reading"}), tiles, table(rd));
    if(Object.keys(data.profile||{}).length){
      d.append(h("h3",{textContent:"Restricted details (never shown on the dashboard or stored readable in the cloud)"}), table(data.profile));
    }
    for(const id of (data.linked_images || [])){
      d.append(h("h3",{textContent:"Captured image"}));
      try{
        const resp = await fetch("/api/vault/image/" + id, {credentials:"same-origin"});
        if(!resp.ok) throw new Error("x");
        const img = h("img",{className:"shot",alt:"Decrypted camera image"});
        img.src = URL.createObjectURL(await resp.blob());
        d.append(img);
      }catch(e){ d.append(h("div",{className:"err",textContent:"Image could not be decrypted."})); }
    }
    d.append(h("div",{className:"note",textContent:"This view is logged. Decrypted data exists only in memory and in this page."}));
  }, delay);
}

function stepEl(s,i){
  const el = h("div",{className:"step" + (s.ok ? "" : " bad")},
    h("div",{className:"dot",textContent:s.ok ? "✓" : "✕"}),
    h("div",{}, h("b",{textContent:s.name}),
      h("span",{textContent:s.detail + (s.ledger_hash ? " · hash " + s.ledger_hash.slice(0,16) + "…" : "")})));
  el.style.animationDelay = (i*350) + "ms";
  return el;
}

$("unlockBtn").onclick = async () => {
  $("err").textContent = "";
  if(!chosen){ $("err").textContent = "Choose a role first."; return; }
  $("unlockBtn").disabled = true;
  try{
    await api("/api/vault/unlock", {method:"POST",
      headers:{"Content-Type":"application/json","X-CSRFToken":csrf},
      body:JSON.stringify({role:chosen, password:$("pw").value})});
    $("pw").value = "";
    init();
  }catch(e){ $("err").textContent = e.message; }
  finally{ $("unlockBtn").disabled = false; }
};
$("pw").addEventListener("keydown", e => { if(e.key === "Enter") $("unlockBtn").click(); });
$("lockBtn").onclick = async () => {
  await api("/api/vault/lock", {method:"POST", headers:{"X-CSRFToken":csrf}});
  $("detail").innerHTML = ""; init();
};

async function init(){
  try{
    await loadCsrf();
    const st = await api("/api/vault/status");
    if(st.unlocked) showOpen(st); else showLocked(st.roles);
  }catch(e){
    if(e.status === 401) location.href = "/login";
    else $("err").textContent = e.message;
  }
}
init();
</script>
</body>
</html>
"""
