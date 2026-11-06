"""Adds Stage 3 (live animated pipeline page) to server.py.

Usage (PowerShell, in the folder that contains server.py):
    python apply_stage3.py
"""
import shutil
import sys
import time
from pathlib import Path

target = Path(sys.argv[1] if len(sys.argv) > 1 else "server.py")
block_file = Path(__file__).resolve().parent / "pipeline_block.py"

if not target.exists() or not block_file.exists():
    sys.exit("Need server.py and pipeline_block.py next to this script.")

raw = target.read_bytes().decode("utf-8")
crlf = "\r\n" in raw
text = raw.replace("\r\n", "\n")

if "# STAGE 1: AUTHORISED VAULT" not in text:
    sys.exit("Apply Stage 1 first. Nothing changed.")

if "# STAGE 3: LIVE PIPELINE TRACE" in text:
    sys.exit("Stage 3 is already applied. Nothing changed.")


def replace_once(source, old, new, label):
    if source.count(old) != 1:
        sys.exit(f"Could not find the {label} (found {source.count(old)}). "
                 "Nothing changed.")
    return source.replace(old, new)


block = block_file.read_text(encoding="utf-8").replace("\r\n", "\n")

# Must come after the Stage 1 (and Stage 2) code, right before start-up.
text = replace_once(text, 'if __name__ == "__main__":',
                    block + '\nif __name__ == "__main__":',
                    "server start-up line")

link_old = "🔐 Authorised area</a>\n"
link_new = (
    "🔐 Authorised area</a>\n"
    '    <a href="/pipeline" style="color:#52d6d0;text-decoration:none;'
    'border:1px solid #52d6d0;border-radius:10px;padding:9px 14px;'
    'font-size:14px">⚡ Live pipeline</a>\n'
)
text = replace_once(text, link_old, link_new, "dashboard header link")

try:
    compile(text, str(target), "exec")
except SyntaxError as exc:
    sys.exit(f"Patched code failed a syntax check ({exc}). Nothing changed.")

backup = target.with_name(f"{target.name}.bak_{time.strftime('%Y%m%d_%H%M%S')}")
shutil.copy2(target, backup)
target.write_bytes((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))
print(f"Done. Backup saved as {backup.name}")
print("Restart server.py, then open the dashboard and click 'Live pipeline'.")
