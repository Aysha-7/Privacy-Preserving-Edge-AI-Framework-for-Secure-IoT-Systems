"""Stage 5: new terminal-style login page and dashboard (same features).

Usage (PowerShell, in the folder that contains server.py):
    python apply_stage5.py
"""
import re
import shutil
import sys
import time
from pathlib import Path

here = Path(__file__).resolve().parent
target = Path(sys.argv[1] if len(sys.argv) > 1 else "server.py")
login_file = here / "login_new.html"
dash_file = here / "dash_new.html"

if not target.exists() or not login_file.exists() or not dash_file.exists():
    sys.exit("Need server.py, login_new.html and dash_new.html next to this script.")

raw = target.read_bytes().decode("utf-8")
crlf = "\r\n" in raw
text = raw.replace("\r\n", "\n")

if "# STAGE 5: TERMINAL UI" in text:
    sys.exit("Stage 5 is already applied. Nothing changed.")

# --- login page
m = re.search(r'LOGIN_PAGE = """\n.*?\n"""\n', text, re.S)
if not m or text.count('LOGIN_PAGE = """') != 1:
    sys.exit("Could not find the login page. Nothing changed.")
login = login_file.read_text(encoding="utf-8").replace("\r\n", "\n")
text = (text[:m.start()] + '# STAGE 5: TERMINAL UI\nLOGIN_PAGE = """\n'
        + login + '"""\n' + text[m.end():])

# --- dashboard
start_marker = "<title>Secure IoT | Monitoring Console</title>"
end_marker = "<script>\nconst $ = id => document.getElementById(id);"
if text.count(start_marker) != 1 or end_marker not in text:
    sys.exit("Could not find the dashboard page. Nothing changed.")
a = text.index(start_marker)
b = text.index(end_marker, a)
if b < a:
    sys.exit("Unexpected dashboard layout. Nothing changed.")
dash = dash_file.read_text(encoding="utf-8").replace("\r\n", "\n")
text = text[:a] + dash + "\n" + text[b:]

try:
    compile(text, str(target), "exec")
except SyntaxError as exc:
    sys.exit(f"Patched code failed a syntax check ({exc}). Nothing changed.")

backup = target.with_name(f"{target.name}.bak_{time.strftime('%Y%m%d_%H%M%S')}")
shutil.copy2(target, backup)
target.write_bytes((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))
print(f"Done. Backup saved as {backup.name}")
print("Restart server.py and open the login page.")
