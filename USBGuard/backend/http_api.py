"""
USB Guard - HTTP API Server
.
"""
import json
import threading
import logging
import datetime
import hashlib
import os
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

PORT = 8765


class APIHandler(BaseHTTPRequestHandler):

    whitelist_module         = None
    audit_module             = None
    auditor_module           = None   # Feature 2 — WhitelistAuditor
    baseline_module          = None   # Feature 3 — BaselineStore
    last_descriptor          = None
    last_threat_descriptor   = None   # Feature 1 — last blocked device
    last_threat_ml_result    = None   # Feature 1 — last blocked ML result
    allow_once_hashes: set   = set()  # Feature 1 — session allow-once set

    def log_message(self, format, *args):
        pass  # suppress default stdout logging

    def do_GET(self):
        if self.path == "/whitelist/list":
            self._json(APIHandler.whitelist_module.list_devices())

        elif self.path == "/audit/list":
            self._json(APIHandler.audit_module.list_entries())

        elif self.path == "/status":
            self._json({"status": "running", "version": "1.1.0"})

        # Feature 2 — whitelist integrity audit status
        elif self.path == "/whitelist/audit":
            if APIHandler.auditor_module:
                self._json(APIHandler.auditor_module.get_status())
            else:
                self._json({"error": "auditor not initialized"})

        # Feature 3 — behavioral baseline list
        elif self.path == "/baseline/list":
            if APIHandler.baseline_module:
                self._json(APIHandler.baseline_module.get_status())
            else:
                self._json([])

        else:
            self._send(404, b"Not found")

    def do_POST(self):
        if self.path == "/whitelist/add_current":
            desc = APIHandler.last_descriptor
            if desc:
                ok = APIHandler.whitelist_module.add_device(desc)
                if ok:
                    # Re-enable every disabled PnP instance with this VID/PID
                    # immediately — covers composite HID children (MI_00, MI_01…)
                    # that were disabled individually and whose device_ids are no
                    # longer visible after the MI_ filter.
                    vid     = desc.get("idVendor",  "")
                    pid     = desc.get("idProduct", "")
                    vid_hex = vid.replace("0x", "").replace("0X", "").upper()
                    pid_hex = pid.replace("0x", "").replace("0X", "").upper()
                    if vid_hex and pid_hex:
                        ps_cmd = (
                            f'Get-PnpDevice -Status Disabled '
                            f'| Where-Object {{ $_.InstanceId -like '
                            f'"*VID_{vid_hex}*PID_{pid_hex}*" }} '
                            f'| Enable-PnpDevice -Confirm:$false'
                        )
                        try:
                            subprocess.run(
                                ["powershell", "-NonInteractive",
                                 "-Command", ps_cmd],
                                capture_output=True, text=True, timeout=20
                            )
                            logger.info(
                                f"Enabled disabled instances for "
                                f"VID_{vid_hex}&PID_{pid_hex} after whitelist add"
                            )
                        except Exception as e:
                            logger.error(f"Enable on whitelist add error: {e}")
                self._json({"success": ok})
            else:
                self._json({"success": False,
                            "error": "No device recently connected"})

        elif self.path.startswith("/whitelist/remove/"):
            device_hash = self.path.split("/")[-1]
            ok = APIHandler.whitelist_module.remove_device(device_hash)
            self._json({"success": ok})

        # Feature 1 — export last threat to a JSON report file
        elif self.path == "/audit/export_threat":
            desc = APIHandler.last_threat_descriptor
            ml   = APIHandler.last_threat_ml_result
            if desc:
                reports_dir = os.path.join(
                    os.path.dirname(__file__), "data", "threat_reports")
                os.makedirs(reports_dir, exist_ok=True)
                ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = os.path.join(reports_dir, f"threat_{ts}.json")
                report   = {
                    "timestamp":  datetime.datetime.now().isoformat(),
                    "descriptor": desc,
                    "ml_result":  ml,
                }
                with open(filename, "w", encoding="utf-8") as fh:
                    json.dump(report, fh, indent=2)
                logger.info(f"Threat report exported: {filename}")
                self._json({"success": True, "file": filename})
            else:
                self._json({"success": False, "error": "No threat recorded yet"})

        # Feature 1 — grant session allow-once for the last blocked device
        elif self.path == "/whitelist/allow_once":
            desc = APIHandler.last_threat_descriptor
            if desc:
                raw = (
                    desc.get("idVendor",      "") +
                    desc.get("idProduct",     "") +
                    desc.get("iManufacturer", "") +
                    desc.get("iProduct",      "")
                )
                device_hash = hashlib.sha256(raw.encode()).hexdigest()
                APIHandler.allow_once_hashes.add(device_hash)
                logger.info(f"Allow-once granted: {device_hash[:16]}…")
                self._json({"success": True})
            else:
                self._json({"success": False, "error": "No threat recorded yet"})

        else:
            self._send(404, b"Not found")

    def _json(self, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type",   "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_api(whitelist_module, audit_module,
              auditor_module=None, baseline_module=None):
    APIHandler.whitelist_module = whitelist_module
    APIHandler.audit_module     = audit_module
    APIHandler.auditor_module   = auditor_module
    APIHandler.baseline_module  = baseline_module
    server = HTTPServer(("localhost", PORT), APIHandler)

    def _run():
        logger.info(f"HTTP API running on http://localhost:{PORT}")
        server.serve_forever()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return server
