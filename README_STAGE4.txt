STAGE 4 - COMMAND CENTER

A) LAPTOP (PowerShell, in the folder with server.py)
   1. Put apply_stage4.py and command_center_block.py in that folder.
   2. python apply_stage4.py        (makes a backup, replaces the old pipeline page)
   3. Restart server.py. Open the dashboard -> "Command center".
   4. Admin PowerShell, once (new Wi-Fi network):
      Set-NetFirewallRule -DisplayName "<your rule name>" -RemoteAddress 192.168.1.0/24

B) DHT11 ESP32 sketch
   1. Copy serial_tee.h into the sketch folder.
   2. After the last #include (after #include "tensorflow/.../schema_generated.h") add:
        #include "serial_tee.h"
   3. In setup(), right after Serial.begin(115200); add:
        startLogSyncHex("http://192.168.1.38:5000/api/device-log", "ESP32_01", "ESP32_01", AES_KEY_HEX);

C) ESP32-CAM sketch
   1. Copy serial_tee.h into the sketch folder.
   2. After the last #include add:  #include "serial_tee.h"
   3. In setup(), right after Serial.begin(115200); add:
        startLogSyncBytes("http://192.168.1.38:5000/api/device-log", "ESP32-CAM", "ESP32-CAM:LOG", AES_KEY);
   4. Change FLASK_URL / FLASK_IMAGE_URL and WIFI_SSID/WIFI_PASSWORD to the current network
      (http://192.168.1.38:5000/api/camera-event and /api/camera-image).

D) Tamper demo: Command center -> tick "I am demonstrating" -> press an attack button.
   Needs at least 2 chain blocks (trigger a couple of events first).
   Always press "Restore the evidence" afterwards.
   Set ATTACK_DEMO=0 in the environment to disable the simulator after the demo.
