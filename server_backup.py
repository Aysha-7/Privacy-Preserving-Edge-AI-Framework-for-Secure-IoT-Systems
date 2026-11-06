
from flask import Flask, request, jsonify
from datetime import datetime, timezone
from pathlib import Path
import csv
import threading

app = Flask(__name__)

DATA_FILE = Path(__file__).resolve().parent / "sensor_data.csv"
CSV_LOCK = threading.Lock()

CSV_COLUMNS = [
    "timestamp_utc",
    "device_id",
    "temperature_c",
    "humidity_percent",
    "prediction",
]

def initialize_csv():
    if not DATA_FILE.exists() or DATA_FILE.stat().st_size == 0:
        with CSV_LOCK:
            with DATA_FILE.open("a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writeheader()

initialize_csv()


@app.get("/")
def home():
    return """
    <!doctype html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>TinyML IoT Monitor</title>
    </head>
    <body style="font-family:Arial;max-width:700px;margin:40px auto;padding:0 15px">
        <h1>TinyML IoT Monitor</h1>
        <p>Python server is running.</p>
        <p>POST sensor records to <code>/api/sensor</code>.</p>
        <p>View the latest records at <a href="/api/latest">/api/latest</a>.</p>
    </body>
    </html>
    """


@app.post("/api/sensor")
def receive_sensor_data():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    required = ["device_id", "temperature", "humidity", "prediction"]
    missing = [key for key in required if key not in data]

    if missing:
        return jsonify({
            "error": "Missing required fields",
            "missing": missing
        }), 400

    try:
        device_id = str(data["device_id"]).strip()
        temperature = float(data["temperature"])
        humidity = float(data["humidity"])
        prediction = str(data["prediction"]).strip().upper()

        if not device_id or len(device_id) > 64:
            raise ValueError("Invalid device_id")

        if not (-40 <= temperature <= 80):
            raise ValueError("Temperature is outside the accepted range")

        if not (0 <= humidity <= 100):
            raise ValueError("Humidity must be between 0 and 100")

        if prediction not in {"NORMAL", "HIGH_HUMIDITY"}:
            raise ValueError("Unknown prediction label")

    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

    timestamp = datetime.now(timezone.utc).isoformat()

    record = {
        "timestamp_utc": timestamp,
        "device_id": device_id,
        "temperature_c": temperature,
        "humidity_percent": humidity,
        "prediction": prediction,
    }

    with CSV_LOCK:
        with DATA_FILE.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writerow(record)

    print(
        f"[{timestamp}] {device_id}: "
        f"{temperature:.1f} C, {humidity:.1f}% RH, {prediction}"
    )

    return jsonify({
        "status": "success",
        "message": "Sensor record saved",
        "record": record
    }), 201


@app.get("/api/latest")
def latest_records():
    count = request.args.get("count", default=20, type=int)
    count = max(1, min(count or 20, 100))

    with CSV_LOCK:
        with DATA_FILE.open("r", newline="", encoding="utf-8") as f:
            records = list(csv.DictReader(f))

    return jsonify({
        "count": min(count, len(records)),
        "records": records[-count:][::-1]
    })


if __name__ == "__main__":
    # Listen on the local network so the ESP32 can reach this computer.
    app.run(host="0.0.0.0", port=5000, debug=False)

