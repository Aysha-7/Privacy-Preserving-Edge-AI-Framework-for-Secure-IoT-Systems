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

@app.get("/api/dashboard-info")
@dashboard_login_required
def dashboard_info():
    return jsonify({
        "csrf_token": __import__("flask_wtf.csrf", fromlist=["generate_csrf"]).generate_csrf()
    })


# --------------------------------------------------
# SECURITY MONITORING DASHBOARD
# --------------------------------------------------

@app.get("/")
@dashboard_login_required
def home():
    return """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure IoT | Monitoring Console</title>
<style>
:root {
    color-scheme: dark;
    --bg: #08111f;
    --panel: #111e30;
    --panel2: #16263b;
    --border: #263b53;
    --text: #edf5ff;
    --muted: #9bb0c8;
    --cyan: #52d6d0;
    --blue: #70a7ff;
    --green: #48d597;
    --red: #ff727f;
    --amber: #f4c76b;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font: 15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif;
}
header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    padding: 20px clamp(16px, 4vw, 48px);
    border-bottom: 1px solid var(--border);
    background: #0b1727;
}
.brand { display:flex; align-items:center; gap:12px; }
.logo {
    display:grid; place-items:center;
    width:44px; height:44px; border-radius:13px;
    background:#123a43; color:var(--cyan);
    font-size:23px;
}
h1 { margin:0; font-size:clamp(20px, 3vw, 27px); }
.subtitle { margin:3px 0 0; color:var(--muted); font-size:13px; }
button {
    min-height:42px; padding:10px 15px;
    border:1px solid var(--border); border-radius:9px;
    background:var(--panel2); color:var(--text);
    font:inherit; cursor:pointer;
}
button:hover { border-color:var(--cyan); }
button:focus-visible { outline:2px solid var(--cyan); outline-offset:3px; }
button.primary { background:#12434a; border-color:#237b7b; }
button:disabled { opacity:.55; cursor:wait; }
main { max-width:1450px; margin:auto; padding:28px clamp(16px, 4vw, 48px); }
.eyebrow {
    color:var(--cyan); text-transform:uppercase;
    letter-spacing:2px; font-size:11px; font-weight:700;
}
.intro { display:flex; justify-content:space-between; gap:20px; align-items:end; flex-wrap:wrap; }
.intro h2 { font-size:clamp(24px, 4vw, 34px); margin:5px 0; }
.muted { color:var(--muted); }
.statusline { display:flex; align-items:center; gap:9px; color:var(--muted); font-size:13px; }
.dot { width:9px; height:9px; border-radius:50%; background:var(--amber); display:inline-block; }
.dot.good { background:var(--green); }
.dot.bad { background:var(--red); }
.grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin:25px 0; }
.card {
    background:var(--panel); border:1px solid var(--border);
    border-radius:15px; padding:19px; min-width:0;
}
.cardtop { display:flex; justify-content:space-between; align-items:center; gap:8px; }
.card h3 { margin:0; font-size:14px; font-weight:600; }
.icon { font-size:21px; }
.value { margin:18px 0 4px; font-size:22px; font-weight:750; overflow-wrap:anywhere; }
.small { color:var(--muted); font-size:12px; overflow-wrap:anywhere; }
.badge {
    display:inline-block; border-radius:20px; padding:4px 8px;
    background:#28364a; color:var(--muted); font-size:11px;
}
.badge.good { background:#12382e; color:var(--green); }
.badge.bad { background:#421e2b; color:var(--red); }
.badge.warn { background:#42351c; color:var(--amber); }
.layout { display:grid; grid-template-columns:minmax(0,1.4fr) minmax(280px,1fr); gap:16px; }
.sectionhead { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:15px; }
.sectionhead h2 { margin:0; font-size:17px; }
.actions { display:flex; gap:8px; flex-wrap:wrap; }
.preview {
    display:grid; place-items:center; min-height:220px; padding:20px;
    border:1px dashed #36516d; border-radius:12px; text-align:center;
    background:radial-gradient(ellipse at center,#162c43,#0c1726);
}
.preview .cameraicon { font-size:38px; }
.preview a { color:var(--cyan); }
.pipeline { display:grid; gap:10px; }
.stage {
    display:flex; gap:12px; align-items:flex-start;
    padding:13px; border-radius:10px; background:#0c1828;
    border:1px solid var(--border);
}
.stageicon {
    display:grid; place-items:center; flex:0 0 32px;
    width:32px; height:32px; border-radius:9px; background:var(--panel2);
}
.stage strong { display:block; font-size:13px; }
.stage p { margin:3px 0 0; font-size:12px; color:var(--muted); overflow-wrap:anywhere; }
.tablewrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th,td { text-align:left; padding:12px 10px; border-bottom:1px solid var(--border); }
th { color:var(--muted); font-weight:500; }
td { overflow-wrap:anywhere; }
.empty { padding:25px 10px; text-align:center; color:var(--muted); }
.footer { margin-top:20px; color:var(--muted); font-size:12px; }
@media(max-width:950px) { .grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .layout { grid-template-columns:1fr; } }
@media(max-width:480px) { header { align-items:flex-start; } .grid { gap:9px; } .card { padding:13px; } .value { font-size:18px; } .hide-mobile { display:none; } }
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo" aria-hidden="true">⬡</div>
    <div>
      <h1>Secure IoT</h1>
      <p class="subtitle">Privacy-preserving edge intelligence</p>
    </div>
  </div>
  <form method="post" action="/logout">
    <input type="hidden" name="csrf_token" id="logoutCsrf">
    <button type="submit">Sign out ↗</button>
  </form>
</header>

<main>
  <section class="intro">
    <div>
      <div class="eyebrow">Security operations / Overview</div>
      <h2>Monitoring console</h2>
      <p class="muted">TinyML detection · AES-256-GCM · Encrypted cloud · Blockchain metadata</p>
    </div>
    <div>
      <div class="statusline"><span class="dot good"></span><span>Dashboard authenticated</span></div>
      <div class="small" id="lastRefresh">Loading system data…</div>
    </div>
  </section>

  <section class="grid" aria-label="System overview">
    <article class="card">
      <div class="cardtop"><h3>Flask backend</h3><span class="icon">⌘</span></div>
      <div class="value" id="flaskValue">Checking…</div>
      <span class="badge" id="flaskBadge">Checking</span>
      <p class="small">Current dashboard session</p>
    </article>
    <article class="card">
      <div class="cardtop"><h3>Camera events</h3><span class="icon">◉</span></div>
      <div class="value" id="cameraCount">—</div>
      <span class="badge" id="cameraBadge">Waiting for data</span>
      <p class="small">Saved anomaly records</p>
    </article>
    <article class="card">
      <div class="cardtop"><h3>Sensor events</h3><span class="icon">⌁</span></div>
      <div class="value" id="sensorCount">—</div>
      <span class="badge" id="sensorBadge">Waiting for data</span>
      <p class="small">Humidity anomaly records</p>
    </article>
    <article class="card">
      <div class="cardtop"><h3>Local integrity</h3><span class="icon">⛨</span></div>
      <div class="value" id="chainValue">Checking…</div>
      <span class="badge" id="chainBadge">Checking</span>
      <p class="small" id="chainDetail">Verifying hash links</p>
    </article>
  </section>

  <section class="layout">
    <article class="card">
      <div class="sectionhead">
        <h2>Camera monitoring</h2>
        <span class="badge" id="cameraConnection">Not checked</span>
      </div>
      <div class="preview">
        <div>
          <div class="cameraicon">📷</div>
          <h3>ESP32-CAM preview</h3>
          <p class="muted" id="previewMessage">Enter your camera's Wi-Fi IP address to open its preview.</p>
          <div class="actions" style="justify-content:center">
            <input id="cameraUrl" type="url" placeholder="http://192.168.1.50" aria-label="Camera base URL" style="max-width:230px;min-width:0;padding:10px;border-radius:8px;border:1px solid var(--border);background:#08111f;color:var(--text)">
            <button class="primary" id="openCamera" type="button">Open preview</button>
          </div>
          <p class="small">Preview is opened separately. This does not start or stop inference on the camera.</p>
        </div>
      </div>
      <div class="sectionhead" style="margin-top:22px">
        <h2>Event activity</h2>
        <button id="refreshBtn" type="button">↻ Refresh data</button>
      </div>
      <div class="tablewrap">
        <table>
          <thead><tr><th>Time</th><th>Device</th><th>Event</th><th>Result</th></tr></thead>
          <tbody id="eventsBody"><tr><td colspan="4" class="empty">Loading event records…</td></tr></tbody>
        </table>
      </div>
    </article>

    <article class="card">
      <div class="sectionhead">
        <h2>Security pipeline</h2>
        <span class="badge">Live checks</span>
      </div>
      <p class="muted" style="font-size:13px">These indicators show checks the backend has actually completed.</p>
      <div class="pipeline">
        <div class="stage"><div class="stageicon">🔐</div><div><strong>Payload authentication</strong><p>ESP32 encrypted payloads are authenticated and decrypted by the server before acceptance.</p><span class="badge" id="cryptoBadge">Ready to validate next event</span></div></div>
        <div class="stage"><div class="stageicon">💾</div><div><strong>Local event storage</strong><p id="localDetail">Reading saved records</p><span class="badge" id="localBadge">Checking</span></div></div>
        <div class="stage"><div class="stageicon">☁️</div><div><strong>Encrypted cloud storage</strong><p>Last reported status for a saved camera event</p><span class="badge" id="cloudBadge">No event status yet</span></div></div>
        <div class="stage"><div class="stageicon">⛓️</div><div><strong>Hyperledger Fabric</strong><p>Last reported metadata submission status for a camera event</p><span class="badge" id="fabricBadge">No event status yet</span></div></div>
      </div>
      <div class="footer">Cloud and Fabric badges reflect the most recent saved camera-event response. They are not continuous external health probes.</div>
    </article>
  </section>
  <p class="footer">Security note: this dashboard does not display encryption keys. Cloud encryption and Fabric metadata verification are handled by the backend verification workflow.</p>
</main>

<script>
const $ = id => document.getElementById(id);
function badge(id, text, state="") {
  const el = $(id);
  el.textContent = text;
  el.className = "badge" + (state ? " " + state : "");
}
function dateText(value) {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
}
function setRows(records) {
  const body = $("eventsBody");
  body.replaceChildren();
  if (!records.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4; td.className = "empty";
    td.textContent = "No sensor records found yet. Camera events are shown when the camera-events endpoint is added.";
    tr.appendChild(td); body.appendChild(tr); return;
  }
  records.slice(0, 20).forEach(r => {
    const tr = document.createElement("tr");
    [dateText(r.timestamp_utc), r.device_id || "—", r.prediction || r.event_type || "Event", r.status || r.prediction || "Recorded"].forEach(v => {
      const td = document.createElement("td"); td.textContent = v; tr.appendChild(td);
    });
    body.appendChild(tr);
  });
}
async function getJSON(url) {
  const response = await fetch(url, {credentials:"same-origin", cache:"no-store"});
  if (response.status === 401) { location.href = "/login"; throw new Error("Please sign in again."); }
  if (!response.ok) throw new Error("Request failed: " + response.status);
  return response.json();
}
async function refreshDashboard() {
  $("refreshBtn").disabled = true;
  $("flaskValue").textContent = "Checking…";
  try {
    const data = await getJSON("/api/latest?count=20");
    $("flaskValue").textContent = "Online";
    badge("flaskBadge", "Responding", "good");
    const records = Array.isArray(data.records) ? data.records : [];
    $("sensorCount").textContent = String(data.count ?? records.length);
    badge("sensorBadge", records.length ? "Records loaded" : "No records yet", records.length ? "good" : "");
    setRows(records);
    $("localDetail").textContent = records.length + " recent sensor record(s) returned by Flask.";
    badge("localBadge", "Readable", "good");
    $("lastRefresh").textContent = "Updated " + new Date().toLocaleTimeString();
  } catch (e) {
    $("flaskValue").textContent = "Unavailable";
    badge("flaskBadge", "Request failed", "bad");
    $("eventsBody").innerHTML = "";
    const tr = document.createElement("tr"), td = document.createElement("td");
    td.colSpan = 4; td.className = "empty"; td.textContent = e.message;
    tr.appendChild(td); $("eventsBody").appendChild(tr);
    badge("localBadge", "Unable to read", "bad");
    $("localDetail").textContent = "The sensor records endpoint did not return data.";
  }
  try {
    const chain = await getJSON("/api/verify-chain");
    if (chain.valid) {
      $("chainValue").textContent = "Valid";
      badge("chainBadge", "Verified", "good");
      $("chainDetail").textContent = (chain.block_count ?? 0) + " block(s) checked";
    } else {
      $("chainValue").textContent = "Warning";
      badge("chainBadge", "Integrity issue", "bad");
      $("chainDetail").textContent = chain.error || "A hash-chain check failed.";
    }
  } catch (e) {
    $("chainValue").textContent = "Unavailable";
    badge("chainBadge", "Check failed", "bad");
    $("chainDetail").textContent = e.message;
  }
  $("cameraCount").textContent = "—";
  badge("cameraBadge", "Camera API not connected");
  $("refreshBtn").disabled = false;
}
$("refreshBtn").addEventListener("click", refreshDashboard);
$("openCamera").addEventListener("click", () => {
  let value = $("cameraUrl").value.trim().replace(/\\/$/, "");
  if (!value) {
    $("previewMessage").textContent = "Enter the ESP32-CAM base URL first.";
    $("cameraConnection").textContent = "URL required";
    return;
  }
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol)) throw new Error();
    $("cameraConnection").textContent = "Opening preview";
    window.open(url.href, "_blank", "noopener,noreferrer");
    $("previewMessage").textContent = "Camera preview opened in another tab. Check that tab for the actual camera image.";
  } catch {
    $("previewMessage").textContent = "Enter a valid camera address, such as http://192.168.1.50.";
    $("cameraConnection").textContent = "Invalid URL";
  }
});
(async () => {
  try {
    $("logoutCsrf").value = await getJSON("/api/dashboard-info").then(x => x.csrf_token);
  } catch {}
})();
refreshDashboard();
setInterval(refreshDashboard, 15000);
</script>
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
def latest_sensor_events():
    """Return recent sensor records to the authenticated dashboard."""
    try:
        count = request.args.get("count", default=20, type=int)
        count = max(1, min(count or 20, 100))

        if not DATA_FILE.exists():
            return jsonify({"events": [], "count": 0})

        with DATA_FILE.open("r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            rows = list(reader)

        rows = rows[-count:]
        rows.reverse()

        return jsonify({
            "events": rows,
            "count": len(rows),
        })

    except (OSError, csv.Error):
        app.logger.exception("Unable to read sensor event history.")
        return jsonify({
            "error": "Sensor event history is temporarily unavailable."
        }), 500


@app.get("/api/camera-events")
@dashboard_login_required
def get_camera_events():
    """Return recent camera event metadata to the authenticated dashboard."""
    events = []
    events_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "camera_events.jsonl",
    )

    if not os.path.exists(events_file):
        return jsonify({
            "events": [],
            "count": 0,
            "message": "No camera events have been saved yet.",
        })

    try:
        with open(events_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)

                    if isinstance(event, dict):
                        events.append(event)
                except json.JSONDecodeError:
                    app.logger.warning(
                        "Skipping an invalid camera event log entry."
                    )

        events = events[-50:]
        events.reverse()

        return jsonify({
            "events": events,
            "count": len(events),
        })

    except OSError:
        app.logger.exception("Unable to read camera event history.")
        return jsonify({
            "error": "Camera event history is temporarily unavailable."
        }), 500


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