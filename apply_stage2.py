"""Adds Stage 2 (HW-627 pulse sensor) to server.py after Stage 1.

Usage (PowerShell, in the folder that contains server.py):
    python apply_stage2.py
"""
import shutil
import sys
import time
from pathlib import Path

target = Path(sys.argv[1] if len(sys.argv) > 1 else "server.py")
block_file = Path(__file__).resolve().parent / "pulse_block.py"

if not target.exists() or not block_file.exists():
    sys.exit("Need server.py and pulse_block.py next to this script.")

raw = target.read_bytes().decode("utf-8")
crlf = "\r\n" in raw
text = raw.replace("\r\n", "\n")

if "# STAGE 1: AUTHORISED VAULT" not in text:
    sys.exit("Apply Stage 1 first (python apply_stage1.py). Nothing changed.")

if "# STAGE 2: HW-627 PULSE SENSOR" in text:
    sys.exit("Stage 2 is already applied. Nothing changed.")


def replace_once(source, old, new, label):
    if source.count(old) != 1:
        sys.exit(f"Could not find the {label} in server.py "
                 f"(found {source.count(old)}). Nothing changed.")
    return source.replace(old, new)


block = block_file.read_text(encoding="utf-8").replace("\r\n", "\n")

# 1. server routes (inserted before the server start-up)
text = replace_once(
    text, 'if __name__ == "__main__":',
    block + '\nif __name__ == "__main__":', "server start-up line")

# 2. main dashboard: also load masked pulse events
text = replace_once(
    text,
    "const [sensorResult, cameraResult, imageResult] = await Promise.allSettled([",
    "const [sensorResult, cameraResult, imageResult, pulseResult] = await Promise.allSettled([",
    "dashboard request list")
text = replace_once(
    text,
    '    getJSON("/api/image-events")\n]);',
    '    getJSON("/api/image-events"),\n    getJSON("/api/pulse-events")\n]);',
    "dashboard image request")
text = replace_once(
    text,
    "    ...imageRecords\n].sort(",
    "    ...imageRecords,\n    ...pulseRowsFrom(pulseResult)\n].sort(",
    "dashboard record merge")
text = replace_once(
    text,
    "async function refreshDashboard() {",
    '''function pulseRowsFrom(result) {
    if (!result || result.status !== "fulfilled") return [];
    const events = Array.isArray(result.value.events) ? result.value.events : [];
    return events.map(event => ({
        ...event,
        status: event.fabric_status || "Recorded"
    }));
}

async function refreshDashboard() {''',
    "refreshDashboard function")

# 3. vault page: draw the heart-rate waveform for the doctor
text = replace_once(
    text,
    'd.append(h("h3",{textContent:"Original reading"}), tiles, table(rd));',
    '''d.append(h("h3",{textContent:"Original reading"}), tiles);
    if(Array.isArray(rd.waveform) && rd.waveform.length){
      d.append(h("h3",{textContent:"Heart-rate trace (decrypted)"}), waveCanvas(rd.waveform));
    }
    d.append(table(Object.fromEntries(Object.entries(rd).filter(([k]) => k !== "waveform"))));''',
    "vault reading renderer")
text = replace_once(
    text,
    "async function openRecord(r){",
    '''function waveCanvas(samples){
  const c = h("canvas",{width:760,height:200});
  c.style.cssText = "width:100%;background:#050c18;border:1px solid var(--line);border-radius:10px";
  const g = c.getContext("2d");
  const lo = Math.min(...samples), hi = Math.max(...samples), span = Math.max(1, hi - lo);
  const pt = i => [i/(samples.length-1)*(c.width-20)+10, c.height-14-((samples[i]-lo)/span)*(c.height-28)];
  let n = matchMedia("(prefers-reduced-motion: reduce)").matches ? samples.length : 1;
  function frame(){
    g.clearRect(0,0,c.width,c.height);
    g.strokeStyle = "#1f3250"; g.lineWidth = 1;
    for(let y=1;y<5;y++){ g.beginPath(); g.moveTo(0,y*c.height/5); g.lineTo(c.width,y*c.height/5); g.stroke(); }
    g.strokeStyle = "#ff6b6b"; g.lineWidth = 2.5; g.lineJoin = "round"; g.shadowColor = "#ff6b6b"; g.shadowBlur = 8;
    g.beginPath();
    for(let i=0;i<n;i++){ const [x,y] = pt(i); i ? g.lineTo(x,y) : g.moveTo(x,y); }
    g.stroke();
    if(n < samples.length){ n = Math.min(samples.length, n + 2); requestAnimationFrame(frame); }
  }
  frame();
  return c;
}

async function openRecord(r){''',
    "vault openRecord function")

try:
    compile(text, str(target), "exec")
except SyntaxError as exc:
    sys.exit(f"Patched code failed a syntax check ({exc}). Nothing changed.")

backup = target.with_name(f"{target.name}.bak_{time.strftime('%Y%m%d_%H%M%S')}")
shutil.copy2(target, backup)
target.write_bytes((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))
print(f"Done. Backup saved as {backup.name}")
print("Next: restart server.py, then add pulse_task.ino to the DHT11 sketch.")
