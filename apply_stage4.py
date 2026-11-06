"""Adds Stage 4 (Command Center) to server.py.

Usage (PowerShell, in the folder that contains server.py):
    python apply_stage4.py
"""
import re
import shutil
import sys
import time
from pathlib import Path

target = Path(sys.argv[1] if len(sys.argv) > 1 else "server.py")
block_file = Path(__file__).resolve().parent / "command_center_block.py"

if not target.exists() or not block_file.exists():
    sys.exit("Need server.py and command_center_block.py next to this script.")

raw = target.read_bytes().decode("utf-8")
crlf = "\r\n" in raw
text = raw.replace("\r\n", "\n")

if "# STAGE 1: AUTHORISED VAULT" not in text:
    sys.exit("Apply Stage 1 first. Nothing changed.")
if "# STAGE 4: COMMAND CENTER" in text:
    sys.exit("Stage 4 is already applied. Nothing changed.")

START = 'if __name__ == "__main__":'
if text.count(START) != 1:
    sys.exit("Could not find the server start-up line. Nothing changed.")

# 1. Remove the old Stage 3 block (it is replaced by the Command Center).
m = re.search(r"# =+\n# STAGE 3: LIVE PIPELINE TRACE", text)
if m:
    end = text.index(START)
    if end < m.start():
        sys.exit("Unexpected layout around Stage 3. Nothing changed.")
    text = text[:m.start()] + text[end:]
    print("Removed the old Stage 3 pipeline block.")

# 2. Add the Command Center just before start-up.
block = block_file.read_text(encoding="utf-8").replace("\r\n", "\n")
text = text.replace(START, block + "\n" + START, 1)

# 3. Dashboard link.
link_re = re.compile(r'    <a href="/pipeline"[^\n]*</a>\n')
new_link = (
    '    <a href="/pipeline" style="color:#52d6d0;text-decoration:none;'
    'border:1px solid #52d6d0;border-radius:10px;padding:9px 14px;'
    'font-size:14px">&#9889; Command center</a>\n'
)
if link_re.search(text):
    text = link_re.sub(lambda _m: new_link, text, count=1)
else:
    anchor = "🔐 Authorised area</a>\n"
    if text.count(anchor) != 1:
        sys.exit("Could not find the dashboard header link. Nothing changed.")
    text = text.replace(anchor, anchor + new_link, 1)

# 4. Remove the decrypting "View Image" button from the dashboard table.
view_re = re.compile(
    r'(?P<i>[ ]+)if \(\n\s+typeof r\.event_id === "string" &&\n'
    r'\s+r\.event_id\.startsWith\("image_"\)\n\s+\) \{\n'
    r'.*?\n\s+\} else \{\n\s+actionCell\.textContent = "—";\n\s+\}\n',
    re.S)
vm = view_re.search(text)
if not vm:
    sys.exit("Could not find the View Image button code. Nothing changed.")
text = (text[:vm.start()] + vm.group("i") + 'actionCell.textContent = "—";\n'
        + text[vm.end():])
if "View Image" in text.split("# STAGE 1: AUTHORISED VAULT")[0]:
    sys.exit("View Image is still present. Nothing changed.")

try:
    compile(text, str(target), "exec")
except SyntaxError as exc:
    sys.exit(f"Patched code failed a syntax check ({exc}). Nothing changed.")

backup = target.with_name(f"{target.name}.bak_{time.strftime('%Y%m%d_%H%M%S')}")
shutil.copy2(target, backup)
target.write_bytes((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))
print(f"Done. Backup saved as {backup.name}")
print("Restart server.py, then open the dashboard and click 'Command center'.")
