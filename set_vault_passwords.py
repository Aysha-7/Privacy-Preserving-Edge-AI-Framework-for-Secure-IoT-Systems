"""Sets the three vault role passwords (stored only as hashes).

Passwords are typed here, hidden, and never shown or saved in plain text.
Run again any time to change a password. Press Enter to skip a role.
"""
import getpass
import os
from pathlib import Path

from werkzeug.security import generate_password_hash

folder = Path(os.environ.get("LOCALAPPDATA", ".")) / "iot_fabric"
folder.mkdir(parents=True, exist_ok=True)

roles = [
    ("factory_manager", "Factory manager"),
    ("doctor", "Doctor"),
    ("homeowner", "Homeowner"),
]

for key, label in roles:
    while True:
        first = getpass.getpass(f"New password for {label} (Enter to skip): ")
        if not first:
            print("  skipped")
            break
        if len(first) < 8:
            print("  use at least 8 characters")
            continue
        if first != getpass.getpass("  type it again: "):
            print("  they did not match, try again")
            continue
        (folder / f"vault_{key}.hash").write_text(
            generate_password_hash(first), encoding="utf-8"
        )
        print("  saved")
        break

print(f"Hashes are in {folder}")
