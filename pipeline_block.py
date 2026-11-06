# ==================================================
# STAGE 3: LIVE PIPELINE TRACE (animated dashboard page)
# ==================================================
# Records the REAL steps of every incoming event (decrypt, hash chain,
# cloud encryption, Cloudinary, Fabric, Telegram) without changing the
# routes: the existing helper functions are wrapped so each one reports
# what it just did. The /pipeline page replays these steps as an animation.
# No sensor values, names or images are ever put in a trace.

import collections
from flask import has_request_context
from flask import g

PIPELINE_RUNS = collections.deque(maxlen=60)
PIPELINE_LOCK = threading.Lock()
PIPELINE_SEQ = [0]

PIPELINE_FLOWS = {
    "/api/sensor": ("humidity", "High-humidity alert", "ESP32 + DHT11"),
    "/api/camera-event": ("camera", "Person detected", "ESP32-CAM"),
    "/api/camera-image": ("image", "Encrypted anomaly image", "ESP32-CAM"),
    "/api/pulse": ("pulse", "Heart-rate anomaly", "ESP32 + HW-627"),
}

PIPELINE_ORDER = [
    "received", "decrypt", "chain", "encrypt_cloud",
    "cloud", "fabric", "alert",
]

PIPELINE_SIGNIFICANT_STEPS = {"encrypt_cloud", "cloud", "fabric", "alert"}


def _pipeline_touch(run):
    PIPELINE_SEQ[0] += 1
    run["seq"] = PIPELINE_SEQ[0]


def pipeline_emit(key, status, detail=""):
    """Add one step to the run of the request being handled (if any)."""

    run = getattr(g, "pipeline_run", None) if has_request_context() else None

    if run is None or run.get("done"):
        return

    with PIPELINE_LOCK:
        run["steps"].append({
            "key": key,
            "status": status,
            "detail": detail,
            "t_ms": int((time.time() - run["_t0"]) * 1000),
        })

        if key in PIPELINE_SIGNIFICANT_STEPS or status == "fail":
            run["significant"] = True

        _pipeline_touch(run)


def _pipeline_finish(http_status):
    run = getattr(g, "pipeline_run", None)

    if run is None or run.get("done"):
        return

    with PIPELINE_LOCK:
        run["done"] = True
        run["http"] = http_status
        run["total_ms"] = int((time.time() - run["_t0"]) * 1000)
        _pipeline_touch(run)


@app.before_request
def _pipeline_begin():
    flow = PIPELINE_FLOWS.get(request.path)

    if flow is None or request.method != "POST":
        return

    run = {
        "id": uuid.uuid4().hex[:10],
        "flow": flow[0],
        "title": flow[1],
        "device": flow[2],
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "steps": [],
        "significant": False,
        "done": False,
        "http": None,
        "_t0": time.time(),
    }

    g.pipeline_run = run

    with PIPELINE_LOCK:
        PIPELINE_RUNS.append(run)
        _pipeline_touch(run)

    pipeline_emit(
        "received", "ok",
        f"Encrypted payload from {flow[2]} ({request.content_length or 0} bytes)",
    )


@app.after_request
def _pipeline_end(response):
    _pipeline_finish(response.status_code)
    return response


@app.teardown_request
def _pipeline_teardown(_error):
    _pipeline_finish(500)


# ---- AES objects: report decrypt / cloud-encrypt as they really happen

class TracedAES:
    def __init__(self, real, kind):
        self._real = real
        self._kind = kind  # "device" or "cloud"

    def decrypt(self, nonce, data, aad):
        try:
            result = self._real.decrypt(nonce, data, aad)
        except Exception:
            if self._kind == "device":
                pipeline_emit(
                    "decrypt", "fail",
                    "Authentication tag INVALID. Message rejected.")
            raise

        if self._kind == "device":
            pipeline_emit(
                "decrypt", "ok",
                "AES-256-GCM tag verified; device identity bound as AAD")

        return result

    def encrypt(self, nonce, data, aad):
        result = self._real.encrypt(nonce, data, aad)

        if self._kind == "cloud":
            pipeline_emit(
                "encrypt_cloud", "ok",
                f"AES-256-GCM with the separate cloud key "
                f"({len(data)} B in, {len(result)} B out)")

        return result


AES = TracedAES(AES, "device")  # noqa: F811
CAMERA_AES = TracedAES(CAMERA_AES, "device")  # noqa: F811
CLOUD_AES = TracedAES(CLOUD_AES, "cloud")  # noqa: F811


# ---- Hash chain

_traced_orig_append_block = append_block


def append_block(event):  # noqa: F811
    block = _traced_orig_append_block(event)

    pipeline_emit(
        "chain", "ok",
        f"Block #{block['index']} linked, hash {block['hash'][:14]}...")

    return block


# ---- Cloudinary

_traced_orig_cloud_upload = cloudinary.uploader.upload


def _traced_cloud_upload(file, *args, **kwargs):
    size = file.getbuffer().nbytes if hasattr(file, "getbuffer") else 0

    try:
        result = _traced_orig_cloud_upload(file, *args, **kwargs)
    except Exception:
        pipeline_emit("cloud", "fail", "Cloudinary upload failed")
        raise

    name = str(result.get("public_id", "")).rsplit("/", 1)[-1]
    pipeline_emit(
        "cloud", "ok",
        f"{size} B of ciphertext stored as {name[:18]}...")

    return result


cloudinary.uploader.upload = _traced_cloud_upload


# ---- Fabric

_traced_orig_fabric = record_event_on_fabric


def record_event_on_fabric(*args, **kwargs):  # noqa: F811
    file_hash = str(kwargs.get("encrypted_file_hash") or (
        args[2] if len(args) > 2 else ""))

    try:
        result = _traced_orig_fabric(*args, **kwargs)
    except Exception:
        pipeline_emit("fabric", "fail", "Fabric did not accept the record")
        raise

    pipeline_emit(
        "fabric", "ok",
        f"Ledger stores SHA-256 {file_hash[:16]}... and the cloud reference")

    return result


# ---- Telegram

_traced_orig_telegram = send_telegram_alert_async


def send_telegram_alert_async(alert_type, message):  # noqa: F811
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        pipeline_emit("alert", "skipped", "Telegram is not configured")
        return _traced_orig_telegram(alert_type, message)

    previous = _TELEGRAM_LAST_SENT.get(alert_type, 0.0)
    suppressed = (
        time.monotonic() - previous < TELEGRAM_ALERT_COOLDOWN_SECONDS
    )

    _traced_orig_telegram(alert_type, message)

    if suppressed:
        pipeline_emit(
            "alert", "skipped",
            "Cooldown active: a similar alert was just sent")
    else:
        pipeline_emit(
            "alert", "ok",
            "Text alert queued: no names, readings or images included")


@app.get("/pipeline")
@dashboard_login_required
def pipeline_page():
    return Response(
        PIPELINE_PAGE,
        mimetype="text/html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/pipeline/runs")
@dashboard_login_required
def pipeline_runs():
    since = request.args.get("since", default=0, type=int)

    with PIPELINE_LOCK:
        runs = [
            {k: v for k, v in run.items() if not k.startswith("_")}
            for run in PIPELINE_RUNS
            if run["seq"] > since and run["significant"]
        ]

        latest = PIPELINE_SEQ[0]

    return jsonify({"latest_seq": latest, "runs": runs})


PIPELINE_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Live Pipeline</title>
<style>
:root{
  --bg:#08111f;--panel:#0e1a2e;--panel2:#12223a;--line:#1f3250;
  --text:#e6eefb;--muted:#8aa0c0;--cyan:#52d6d0;--green:#4ade80;
  --red:#ff6b6b;--amber:#fbbf24;--violet:#a78bfa;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 20% -10%,#12315a66,transparent),var(--bg);
  color:var(--text);font-family:system-ui,Segoe UI,Roboto,sans-serif;min-height:100vh}
header{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;
  border-bottom:1px solid var(--line);gap:12px;flex-wrap:wrap}
a.back{color:var(--cyan);text-decoration:none;font-size:14px}
h1{font-size:18px;margin:0;letter-spacing:.04em;text-align:center}
.sub{color:var(--muted);font-size:12px;text-align:center}
.live{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--muted)}
.dot{width:10px;height:10px;border-radius:50%;background:var(--green);box-shadow:0 0 0 0 #4ade8080;animation:ping 2s infinite}
@keyframes ping{70%{box-shadow:0 0 0 10px #4ade8000}100%{box-shadow:0 0 0 0 #4ade8000}}
main{max-width:1180px;margin:0 auto;padding:18px 14px 50px}
.stage{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:14px 8px 6px;overflow:hidden}
.runhead{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:0 10px 8px}
.runhead b{font-size:17px}
.runhead span{color:var(--muted);font-size:13px}
svg{width:100%;height:auto;display:block}
.node rect{fill:#0b1830;stroke:var(--line);stroke-width:1.5;transition:stroke .3s,fill .3s}
.node text{fill:var(--text);text-anchor:middle}
.node .t{font-size:15px;font-weight:600}
.node .s{font-size:11px;fill:var(--muted)}
.node .ic{font-size:28px}
.node.active rect{stroke:var(--cyan);fill:#0e2a3d;filter:drop-shadow(0 0 10px #52d6d0aa)}
.node.ok rect{stroke:var(--green)}
.node.fail rect{stroke:var(--red);fill:#2a1220}
.node.skip{opacity:.45}
.node.skip rect{stroke-dasharray:5 5}
.badge{font-size:15px;font-weight:700;text-anchor:middle}
.link{stroke:var(--line);stroke-width:3;stroke-linecap:round;transition:stroke .3s}
.link.on{stroke:var(--cyan)}
.packet{fill:var(--cyan);filter:drop-shadow(0 0 8px #52d6d0)}
.now{display:grid;grid-template-columns:1.1fr 1fr;gap:14px;margin-top:14px}
@media(max-width:860px){.now{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:16px}
.card h2{margin:0 0 6px;font-size:13px;color:var(--muted);letter-spacing:.12em;text-transform:uppercase}
#nowTitle{font-size:22px;font-weight:700;margin:4px 0}
#nowText{color:var(--muted);line-height:1.5;min-height:48px}
#nowDetail{margin-top:10px;font-family:ui-monospace,Consolas,monospace;font-size:13px;color:var(--cyan);
  background:#06101f;border:1px solid var(--line);border-radius:10px;padding:10px;min-height:42px;word-break:break-all}
.log{list-style:none;margin:0;padding:0;font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
.log li{display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--line);opacity:0;animation:in .35s forwards}
@keyframes in{to{opacity:1}}
.log .ms{color:var(--muted);min-width:58px}
.log .ok{color:var(--green)}.log .fail{color:var(--red)}.log .skipped{color:var(--amber)}
.recent{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px}
.chip{background:var(--panel2);border:1px solid var(--line);color:var(--text);border-radius:99px;padding:7px 12px;
  font-size:13px;cursor:pointer}
.chip:hover{border-color:var(--cyan)}
.summary{margin-top:10px;padding:10px 12px;border-radius:10px;background:#0c2a22;border:1px solid #1d6b4d;color:#a7f3d0;display:none}
.summary.bad{background:#2a1220;border-color:#7a2a3d;color:#fecaca}
.idle{color:var(--muted);text-align:center;padding:6px}
@media(prefers-reduced-motion:reduce){*{animation-duration:.01s!important;transition:none!important}}
</style>
</head>
<body>
<header>
  <a class="back" href="/">&larr; Dashboard</a>
  <div><h1>Live security pipeline</h1><div class="sub">What the backend really does with each event</div></div>
  <div class="live"><span class="dot"></span><span id="liveText">listening</span></div>
</header>
<main>
  <div class="stage">
    <div class="runhead"><b id="runTitle">Waiting for the next event</b><span id="runMeta">Trigger the sensor, camera or pulse node</span></div>
    <svg id="svg" viewBox="0 0 1100 215" role="img" aria-label="Pipeline diagram"></svg>
    <div class="summary" id="summary"></div>
  </div>

  <div class="now">
    <div class="card">
      <h2>Now happening</h2>
      <div id="nowTitle">Idle</div>
      <div id="nowText">The pipeline lights up as soon as a device sends an event. Every step you see is real: it is reported by the server while it handles the request.</div>
      <div id="nowDetail">&nbsp;</div>
    </div>
    <div class="card">
      <h2>Step log (real timings)</h2>
      <ul class="log" id="log"></ul>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <h2>Recent events (click to replay)</h2>
    <div class="recent" id="recent"><span class="idle">No events yet.</span></div>
  </div>
</main>

<script>
const $ = id => document.getElementById(id);
const NS = "http://www.w3.org/2000/svg";
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
const sleep = ms => new Promise(r => setTimeout(r, reduce ? Math.min(ms, 40) : ms));

const STEPS = [
  {key:"received", icon:"\u{1F4E1}", title:"Device", sub:"Encrypted on-device",
   text:"The ESP32 encrypted its reading before sending. Only ciphertext crosses the network."},
  {key:"decrypt", icon:"\u{1F513}", title:"Flask verify", sub:"Tag check + decrypt",
   text:"Flask checks the authentication tag. A forged or modified message is rejected right here."},
  {key:"chain", icon:"⛓", title:"Hash chain", sub:"SHA-256 linked block",
   text:"The event joins a local hash chain. Changing any old block would break every later hash."},
  {key:"encrypt_cloud", icon:"\u{1F510}", title:"Re-encrypt", sub:"Cloud key + private profile",
   text:"The server encrypts again with a separate cloud key. Private device details go inside the ciphertext."},
  {key:"cloud", icon:"☁", title:"Cloudinary", sub:"Ciphertext only",
   text:"The cloud receives unreadable bytes. Without the key it learns nothing."},
  {key:"fabric", icon:"\u{1F9FE}", title:"Fabric ledger", sub:"Hash + reference",
   text:"Hyperledger Fabric records only the file's SHA-256 and its reference, so any later change is detectable."},
  {key:"alert", icon:"\u{1F4E8}", title:"Telegram", sub:"Alert, no private data",
   text:"Telegram gets a short alert. Names, readings and images stay behind the authorised login."}
];
const X0 = 10, GAP = 155, W = 120, Y = 40, H = 120;
const nodes = {}, links = [];
const svg = $("svg");

function el(tag, attrs, parent, text){
  const e = document.createElementNS(NS, tag);
  for(const k in attrs) e.setAttribute(k, attrs[k]);
  if(text !== undefined) e.textContent = text;
  (parent || svg).appendChild(e);
  return e;
}

STEPS.forEach((s, i) => {
  const x = X0 + i*GAP;
  if(i < STEPS.length - 1){
    links.push(el("line", {class:"link", x1:x+W, y1:Y+H/2, x2:x+GAP, y2:Y+H/2}));
  }
  const g = el("g", {class:"node"});
  el("rect", {x, y:Y, width:W, height:H, rx:16}, g);
  el("text", {class:"ic", x:x+W/2, y:Y+44}, g, s.icon);
  const t = el("text", {class:"t", x:x+W/2, y:Y+74}, g, s.title);
  el("text", {class:"s", x:x+W/2, y:Y+93}, g, s.sub);
  const b = el("text", {class:"badge", x:x+W/2, y:Y+H+30}, g, "");
  nodes[s.key] = {g, t, b, cx:x+W/2, cy:Y+H/2, left:x, right:x+W};
});
const packet = el("circle", {class:"packet", r:9, cx:-50, cy:Y+H/2});

let token = 0, queue = [], playing = false, lastSeq = 0, played = new Set(), history = [];

function resetView(){
  STEPS.forEach(s => { nodes[s.key].g.setAttribute("class", "node"); nodes[s.key].b.textContent = ""; });
  links.forEach(l => l.setAttribute("class", "link"));
  packet.setAttribute("cx", -50);
  packet.setAttribute("opacity", 0);
  $("log").innerHTML = "";
  $("summary").style.display = "none";
  $("summary").className = "summary";
}

function setNode(key, cls, badge, color){
  nodes[key].g.setAttribute("class", "node " + cls);
  nodes[key].b.textContent = badge || "";
  nodes[key].b.setAttribute("fill", color || "#e6eefb");
}

async function movePacket(fromX, toX, my){
  const ms = reduce ? 30 : 650;
  const start = performance.now();
  return new Promise(res => {
    const tick = now => {
      if(my !== token){ res(); return; }
      const p = Math.min(1, (now - start)/ms);
      const e = p<.5 ? 2*p*p : 1-Math.pow(-2*p+2,2)/2;
      packet.setAttribute("cx", fromX + (toX-fromX)*e);
      p < 1 ? requestAnimationFrame(tick) : res();
    };
    requestAnimationFrame(tick);
  });
}

async function typeText(node, text, my){
  node.textContent = "";
  if(reduce){ node.textContent = text; return; }
  for(let i=1;i<=text.length;i++){
    if(my !== token) return;
    node.textContent = text.slice(0,i);
    await sleep(12);
  }
}

function addLog(step, label){
  const li = document.createElement("li");
  const ms = document.createElement("span"); ms.className = "ms"; ms.textContent = "+" + step.t_ms + " ms";
  const st = document.createElement("span"); st.className = step.status;
  st.textContent = step.status === "ok" ? "✓" : step.status === "fail" ? "✕" : "–";
  const tx = document.createElement("span"); tx.textContent = label + ": " + step.detail;
  li.append(ms, st, tx);
  $("log").appendChild(li);
}

async function playRun(run){
  const my = ++token;
  resetView();
  $("runTitle").textContent = run.title;
  $("runMeta").textContent = run.device + " · " + new Date(run.started_utc).toLocaleTimeString();
  nodes.received.t.textContent = run.device.split(" ")[0] === "ESP32-CAM" ? "ESP32-CAM" : "ESP32";
  $("liveText").textContent = "playing";
  let prevKey = null, failed = false;

  for(const s of STEPS){
    if(my !== token) return;
    const step = run.steps.find(x => x.key === s.key);

    if(failed || !step){
      setNode(s.key, "skip", "–", "#8aa0c0");
      await sleep(failed ? 60 : 160);
      continue;
    }

    if(prevKey){
      links.forEach(l => l.setAttribute("class", "link"));
      const idx = STEPS.findIndex(x => x.key === prevKey);
      links[idx].setAttribute("class", "link on");
      packet.setAttribute("opacity", 1);
      await movePacket(nodes[prevKey].right, nodes[s.key].left, my);
      packet.setAttribute("opacity", 0);
    }
    if(my !== token) return;

    setNode(s.key, "active", "…", "#52d6d0");
    $("nowTitle").textContent = s.title + " — " + s.sub;
    $("nowText").textContent = s.text;
    await typeText($("nowDetail"), step.detail || "", my);
    await sleep(step.status === "fail" ? 900 : 420);
    if(my !== token) return;

    if(step.status === "ok") setNode(s.key, "ok", "✓", "#4ade80");
    else if(step.status === "fail"){ setNode(s.key, "fail", "✕", "#ff6b6b"); failed = true; }
    else setNode(s.key, "skip", "–", "#fbbf24");
    addLog(step, s.title);
    prevKey = s.key;
  }

  if(my !== token) return;
  const box = $("summary");
  const good = !failed && run.http && run.http < 300;
  box.className = "summary" + (good ? "" : " bad");
  box.textContent = good
    ? "Completed in " + run.total_ms + " ms. The event is encrypted, chained, stored and recorded on the ledger."
    : (failed ? "Stopped: a check failed, so nothing further was stored." : "Finished with HTTP " + run.http + ".");
  box.style.display = "block";
  $("nowTitle").textContent = good ? "Done" : "Stopped";
  $("nowText").textContent = good ? "Open the Authorised area to decrypt and read the details." : "See the step log for the reason.";
  $("liveText").textContent = "listening";
}

async function pump(){
  if(playing) return;
  playing = true;
  while(queue.length){
    const run = queue.shift();
    await playRun(run);
    await sleep(1200);
  }
  playing = false;
}

function renderRecent(){
  const box = $("recent");
  box.innerHTML = "";
  if(!history.length){ box.innerHTML = '<span class="idle">No events yet.</span>'; return; }
  history.slice().reverse().slice(0, 14).forEach(run => {
    const b = document.createElement("button");
    b.className = "chip";
    b.textContent = new Date(run.started_utc).toLocaleTimeString() + " · " + run.title;
    b.onclick = () => { queue = [run]; token++; pump(); };
    box.appendChild(b);
  });
}

async function poll(first){
  try{
    const r = await fetch("/api/pipeline/runs?since=" + (first ? 0 : lastSeq), {credentials:"same-origin"});
    if(r.status === 401){ location.href = "/login"; return; }
    const data = await r.json();
    lastSeq = data.latest_seq;

    for(const run of data.runs){
      const known = history.findIndex(h => h.id === run.id);
      if(known >= 0) history[known] = run; else history.push(run);

      if(first || !run.done || played.has(run.id)) continue;
      played.add(run.id);
      queue.push(run);
    }
    if(first) data.runs.forEach(r => { if(r.done) played.add(r.id); });
    while(queue.length > 4) queue.shift();
    renderRecent();
    pump();
  }catch(e){ $("liveText").textContent = "reconnecting"; }
}

poll(true);
setInterval(() => poll(false), 1000);
</script>
</body>
</html>
"""
