"""Adds the Stage 1 encrypted vault to server.py (safe: makes a backup first).

Usage (PowerShell, in the folder that contains server.py):
    python apply_stage1.py            # patches server.py
    python apply_stage1.py other.py   # patches another file name
"""
import shutil
import sys
import time
from pathlib import Path

MARKER = "# STAGE 1: AUTHORISED VAULT"
target = Path(sys.argv[1] if len(sys.argv) > 1 else "server.py")
block_file = Path(__file__).resolve().parent / "vault_block.py"

if not target.exists() or not block_file.exists():
    sys.exit("Need server.py and vault_block.py in the same folder as this script.")

raw = target.read_bytes().decode("utf-8")
crlf = "\r\n" in raw
text = raw.replace("\r\n", "\n")

if MARKER in text:
    sys.exit("Stage 1 is already applied. Nothing changed.")

block = block_file.read_text(encoding="utf-8").replace("\r\n", "\n")

# 1. insert the vault block before the server start-up
main_anchor = 'if __name__ == "__main__":'
if text.count(main_anchor) != 1:
    sys.exit("Could not find the single 'if __name__' line. Nothing changed.")
text = text.replace(main_anchor, block + "\n\n" + main_anchor)

# 2. add a link to the authorised area in the dashboard header
old = (
    '    <form method="post" action="/logout">\n'
    '        <input type="hidden" name="csrf_token" id="logoutCsrf">\n'
    '        <button type="submit">Sign out ↗</button>\n'
    '    </form>\n'
)
new = (
    '    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">\n'
    '    <a href="/vault" style="color:#52d6d0;text-decoration:none;'
    'border:1px solid #52d6d0;border-radius:10px;padding:9px 14px;'
    'font-size:14px">🔐 Authorised area</a>\n'
    + old.replace("    <form", "    <form", 1).rstrip("\n") + "\n"
    '    </div>\n'
)
if text.count(old) != 1:
    sys.exit("Could not find the header sign-out form. Nothing changed.")
text = text.replace(old, new)

# 3. make sure the result is valid Python before writing anything
try:
    compile(text, str(target), "exec")
except SyntaxError as exc:
    sys.exit(f"Patched code failed a syntax check ({exc}). Nothing changed.")

backup = target.with_name(f"{target.name}.bak_{time.strftime('%Y%m%d_%H%M%S')}")
shutil.copy2(target, backup)

out = text.replace("\n", "\r\n") if crlf else text
target.write_bytes(out.encode("utf-8"))
print(f"Done. Backup saved as {backup.name}")
print("Next: python set_vault_passwords.py   then restart server.py")
