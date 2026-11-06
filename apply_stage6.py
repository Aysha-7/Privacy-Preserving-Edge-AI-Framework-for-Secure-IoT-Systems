"""Stage 6: tamper reset, 'Armed and watching' on unplug, console status,
rejected-packet diagnostics, and the green terminal look for the vault.

Needs Stage 4 already applied. Safe to run more than once.
Usage (PowerShell, in the folder that contains server.py):
    python apply_stage6.py
"""
import re
import shutil
import sys
import time
from pathlib import Path

here = Path(__file__).resolve().parent
target = Path(sys.argv[1] if len(sys.argv) > 1 else "server.py")
files = {n: here / n for n in (
    "command_center_block.py", "dash_new.html", "vault_new.html",
    "login_new.html")}

if not target.exists() or not all(p.exists() for p in files.values()):
    sys.exit("Need server.py and the four stage 6 files next to this script.")

raw = target.read_bytes().decode("utf-8")
crlf = "\r\n" in raw
text = raw.replace("\r\n", "\n")
START = 'if __name__ == "__main__":'

if "# STAGE 4: COMMAND CENTER" not in text:
    sys.exit("Apply Stage 4 first. Nothing changed.")
if text.count(START) != 1:
    sys.exit("Could not find the server start-up line. Nothing changed.")


def read(name):
    return files[name].read_text(encoding="utf-8").replace("\r\n", "\n")


# 1. Command Center server code + page
m = re.search(r"# =+\n# STAGE 4: COMMAND CENTER", text)
end = text.index(START)
if end < m.start():
    sys.exit("Unexpected layout. Nothing changed.")
text = text[:m.start()] + read("command_center_block.py") + "\n" + text[end:]

# 2. Dashboard
a_mark = "<title>Secure IoT | Monitoring Console</title>"
b_mark = "<script>\nconst $ = id => document.getElementById(id);"
a = text.index(a_mark)
b = text.index(b_mark, a)
text = text[:a] + read("dash_new.html") + "\n" + text[b:]

# 3. Login (only if Stage 5 was not applied before)
if "# STAGE 5: TERMINAL UI" not in text:
    m = re.search(r'LOGIN_PAGE = """\n.*?\n"""\n', text, re.S)
    if not m:
        sys.exit("Could not find the login page. Nothing changed.")
    text = (text[:m.start()] + '# STAGE 5: TERMINAL UI\nLOGIN_PAGE = """\n'
            + read("login_new.html") + '"""\n' + text[m.end():])

# 4. Vault
v_mark = "<title>Authorised Personnel Only</title>"
v_end = ("<script>\nconst $ = id => document.getElementById(id);\n"
         "const ICONS")
if text.count(v_mark) != 1 or text.count(v_end) != 1:
    sys.exit("Could not find the vault page. Nothing changed.")
a = text.index(v_mark)
b = text.index(v_end)
vault = read("vault_new.html")
text = text[:a] + vault + "\n" + text[b:]

for old, new in (
    ('const ICONS = {factory_manager:"\\u{1F3ED}", doctor:"\\u{1FA7A}", '
     'homeowner:"\\u{1F3E0}"};',
     'const ICONS = {factory_manager:"[FAC]", doctor:"[DOC]", '
     'homeowner:"[HOME]"};'),
    ('|| "\\u{1F512}"', '|| "[LOCK]"'),
    ('"\\u{1F513} auto-locks in "', '"auto-locks in "'),
):
    if text.count(old) == 1:
        text = text.replace(old, new)
    elif text.count(new) < 1:
        sys.exit(f"Vault script changed unexpectedly ({old[:30]}). "
                 "Nothing changed.")

try:
    compile(text, str(target), "exec")
except SyntaxError as exc:
    sys.exit(f"Patched code failed a syntax check ({exc}). Nothing changed.")

backup = target.with_name(f"{target.name}.bak_{time.strftime('%Y%m%d_%H%M%S')}")
shutil.copy2(target, backup)
target.write_bytes((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))
print(f"Done. Backup saved as {backup.name}")
print("Restart server.py.")
