import os
import json
import urllib.request
import urllib.error

event_id = "event_cca7b2ded2fe4d61876ba8502151833a"
url = "http://localhost:8080/events/" + event_id
token = os.environ.get("FABRIC_GATEWAY_TOKEN")

if not token:
    print("Gateway token is missing from this CMD environment.")
    raise SystemExit(1)

req = urllib.request.Request(
    url,
    headers={"Authorization": "Bearer " + token}
)

try:
    with urllib.request.urlopen(req, timeout=15) as response:
        print("HTTP status:", response.status)
        print(response.read().decode())
except urllib.error.HTTPError as e:
    print("HTTP status:", e.code)
    print(e.read().decode())
except Exception as e:
    print(type(e).__name__ + ":", e)