"""
USB Guard v1.0 - Main Entry Point
Orchestrates the full five-stage USB Rubber Ducky detection pipeline.
"""
import logging
import time
import threading
import subprocess
import os
import sys

#  Logging setup 
LOG_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(LOG_DIR, "usb_guard.log"),
                            encoding="utf-8"),
    ]
)
logger = logging.getLogger(__name__)

# Module imports 
from usb_detection       import USBDetectionModule
from descriptor_check    import DescriptorChecker
from behavioural_sandbox import BehaviouralSandbox
from ml_engine           import MLEngine
from whitelist           import WhitelistModule
from audit_log           import AuditLogger
from ipc_server          import IPCServer
from http_api            import start_api, APIHandler
from whitelist_auditor   import WhitelistAuditor   # Feature 2
from baseline_store      import BaselineStore       # Feature 3


class USBGuard:
    

    def __init__(self):
        self.whitelist      = WhitelistModule()
        self.checker        = DescriptorChecker()
        self.sandbox        = BehaviouralSandbox()
        self.ml             = MLEngine()
        self.audit          = AuditLogger()
        self.ipc            = IPCServer()
        self._last_desc     = None
        self._blocked_count = 0
        self._allowed_count = 0
        self._start_time    = time.time()

        self.auditor  = WhitelistAuditor(self.ipc)  # Feature 2
        self.baseline = BaselineStore()             # Feature 3

        self.detector = USBDetectionModule(
            on_device_connected=self.on_device_connected
        )

    def start(self):
        logger.info("=" * 55)
        logger.info("  USB Guard v1.0  -  Ducky Detection System")
        logger.info("  ISP-14  |  SLIIT  |  Cyber Security")
        logger.info("=" * 55)

        # Verify audit log chain integrity
        ok = self.audit.verify_chain()
        if not ok:
            logger.critical(
                "Audit log integrity check FAILED. "
                "Possible tampering detected. Halting."
            )
            return

        # Heal any devices disabled by a previous session before opening to traffic
        self._heal_disabled_devices()

        # Start IPC named pipe server
        self.ipc.start()

        # Feature 2 — start whitelist integrity auditor
        self.auditor.start()

        # Start HTTP REST API
        start_api(self.whitelist, self.audit, self.auditor, self.baseline)
        APIHandler.last_descriptor = None

        # Start USB detection listener
        self.detector.start()

        logger.info(f"IPC pipe  : \\\\.\\pipe\\USBGuardIPC")
        logger.info(f"HTTP API  : http://localhost:8765")
        logger.info("Monitoring all USB ports...")
        logger.info("=" * 55)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutdown requested.")
            self.detector.stop()
            self.ipc.stop()
            logger.info("USB Guard stopped.")

    #  Pipeline 

    def on_device_connected(self, descriptor: dict):
        self._last_desc          = descriptor
        APIHandler.last_descriptor = descriptor

        vid  = descriptor.get("idVendor",  "?")
        pid  = descriptor.get("idProduct", "?")
        name = descriptor.get("iProduct",  "Unknown")

        logger.info(f"Device connected: {vid}:{pid}  [{name}]")

        self.ipc.send("device_connected", {"descriptor": descriptor})

        # Feature 1 — session allow-once override (set via API after user confirms toast)
        _dh = self.whitelist.device_hash(descriptor)
        if _dh in APIHandler.allow_once_hashes:
            APIHandler.allow_once_hashes.discard(_dh)
            logger.info("Stage 0 ALLOW — Device in session allow-once list.")
            self._allow(descriptor, {
                "score": 0.0, "anomaly": False,
                "decision": "ALLOW_ONCE", "features": {}
            }, reason="allow_once_session")
            return

        #  Stage 1: Whitelist check
        if self.whitelist.is_trusted(descriptor):
            logger.info("Stage 1 PASS — Device whitelisted.")
            self._allow(descriptor, {
                "score": 0.0, "anomaly": False,
                "decision": "ALLOW_WHITELIST", "features": {}
            }, reason="whitelisted")
            return

        # Stage 2: Descriptor screening 
        check = self.checker.check(descriptor)

        if check["result"] == "BLOCK_IMMEDIATE":
            logger.warning("Stage 2 BLOCK — Known malicious descriptor.")
            self._block(descriptor, {
                "score": 1.0, "anomaly": True,
                "decision": "BLOCK", "features": {}
            }, reason="known_malicious_descriptor")
            return

        if check["result"] == "ALLOW":
            logger.info("Stage 2 PASS — Non-keyboard device, logged and allowed.")
            self._allow(descriptor, {
                "score": 0.0, "anomaly": False,
                "decision": "ALLOW", "features": {}
            }, reason="non_keyboard_device")
            return

        #  Stage 3: Behavioural sandbox 
        logger.info("Stage 3 — Running behavioural sandbox (500ms)...")
        self.ipc.send("pipeline_update", {
            "stage": "sandbox_start", "descriptor": descriptor
        })

        features = self.sandbox.analyse()

        # Stage 4: ML classification 
        logger.info("Stage 4 — ML classification...")
        ml_result = self.ml.classify(features)

        self.ipc.send("pipeline_update", {
            "stage":      "ml_complete",
            "descriptor": descriptor,
            "features":   features,
            "ml_result":  ml_result
        })

        #  Stage 5: Enforce decision 
        if ml_result["decision"] == "BLOCK":
            logger.warning(
                f"Stage 5 BLOCK — ML score {ml_result['score']:.2f} "
                f"exceeds threshold 0.50."
            )
            self._block(descriptor, ml_result, reason="ml_classifier")
        else:
            logger.info(
                f"Stage 5 ALLOW — ML score {ml_result['score']:.2f} "
                f"below threshold 0.50."
            )
            self._allow(descriptor, ml_result, reason="ml_classifier")

    #  Actions 

    def _block(self, descriptor: dict, ml_result: dict, reason: str = ""):
        self._blocked_count += 1
        self._disable_port(descriptor.get("device_id", ""))
        self.audit.write(descriptor, ml_result)
        # Feature 1 — cache for report export and allow-once API
        APIHandler.last_threat_descriptor = descriptor
        APIHandler.last_threat_ml_result  = ml_result
        self.ipc.send("threat_detected", {
            "descriptor":    descriptor,
            "ml_result":     ml_result,
            "reason":        reason,
            "blocked_count": self._blocked_count,
            "uptime_seconds": int(time.time() - self._start_time)
        })

    def _allow(self, descriptor: dict, ml_result: dict, reason: str = ""):
        self._allowed_count += 1
        # Re-enable ALL disabled PnP instances for this VID/PID (async so
        # the pipeline is not blocked by the PowerShell call).
        threading.Thread(
            target=self._enable_by_vid_pid,
            args=(descriptor.get("idVendor", ""), descriptor.get("idProduct", "")),
            daemon=True
        ).start()
        self.audit.write(descriptor, ml_result)
        # Feature 3 — compare against baseline first, then update it
        features = ml_result.get("features", {})
        if features:
            _dh   = self.whitelist.device_hash(descriptor)
            drift = self.baseline.compare_baseline(_dh, features)
            self.baseline.update_baseline(_dh, features)
            if drift.get("drift_score") is not None and drift["drift_score"] > 5.0:
                logger.warning(
                    f"Behavioral drift detected: {drift['drift_score']:.2f} "
                    f"(baseline n={drift.get('sample_count', 0)})"
                )
                self.ipc.send("baseline_drift", {
                    "descriptor": descriptor,
                    "drift":      drift,
                })
        self.ipc.send("device_allowed", {
            "descriptor":    descriptor,
            "ml_result":     ml_result,
            "reason":        reason,
            "allowed_count": self._allowed_count,
            "uptime_seconds": int(time.time() - self._start_time)
        })

    def _disable_port(self, device_id: str):
        """
        Disable USB port via pnputil (v1.0 interim measure).
        v1.1 will use a signed WDK kernel driver via DeviceIoControl.
        """
        if not device_id:
            logger.warning("No device_id — cannot disable port.")
            return
        try:
            result = subprocess.run(
                ["pnputil", "/disable-device", device_id],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.info(f"USB port disabled: {device_id}")
            else:
                logger.warning(
                    f"pnputil returned non-zero: {result.stderr.strip()}"
                )
        except FileNotFoundError:
            logger.error("pnputil not found — port not disabled.")
        except subprocess.TimeoutExpired:
            logger.error("pnputil timed out — port not disabled.")
        except Exception as e:
            logger.error(f"Port disable error: {e}")

    def _enable_port(self, device_id: str):
        """Re-enable a USB device that was previously disabled by _disable_port."""
        if not device_id:
            return
        try:
            result = subprocess.run(
                ["pnputil", "/enable-device", device_id],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.info(f"USB port re-enabled: {device_id}")
            else:
                logger.debug(
                    f"pnputil enable non-zero (device may already be enabled): "
                    f"{result.stderr.strip()}"
                )
        except FileNotFoundError:
            logger.error("pnputil not found — cannot re-enable port.")
        except subprocess.TimeoutExpired:
            logger.error("pnputil timed out — port not re-enabled.")
        except Exception as e:
            logger.error(f"Port enable error: {e}")

    def _enable_by_vid_pid(self, vid: str, pid: str):
        """
        Find every disabled PnP device instance that matches a VID/PID pair
        and enable it.  Handles composite USB devices whose HID child interfaces
        (MI_00, MI_01, …) were individually disabled — the MI_ filter means
        those child device_ids never reach _enable_port directly, so we must
        search by VID/PID instead.
        Uses PowerShell Get-PnpDevice which is available on all Windows 10/11.
        """
        if not vid or not pid:
            return
        vid_hex = vid.replace("0x", "").replace("0X", "").upper()
        pid_hex = pid.replace("0x", "").replace("0X", "").upper()
        ps_cmd  = (
            f'Get-PnpDevice -Status Disabled '
            f'| Where-Object {{ $_.InstanceId -like "*VID_{vid_hex}*PID_{pid_hex}*" }} '
            f'| Enable-PnpDevice -Confirm:$false'
        )
        try:
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0:
                logger.info(
                    f"Re-enabled disabled devices for VID_{vid_hex}&PID_{pid_hex}"
                )
            else:
                logger.debug(
                    f"PowerShell enable: {result.stderr.strip() or '(no output)'}"
                )
        except FileNotFoundError:
            logger.error("powershell not found — falling back to pnputil.")
            self._enable_port(f"USB\\VID_{vid_hex}&PID_{pid_hex}")
        except subprocess.TimeoutExpired:
            logger.error("PowerShell enable timed out.")
        except Exception as e:
            logger.error(f"Enable by VID/PID error: {e}")

    def _heal_disabled_devices(self):
        """
        On startup, re-enable any PnP device whose VID/PID is in the whitelist
        but whose driver is currently disabled in Device Manager.  This repairs
        devices that were blocked in a previous session without requiring the
        user to unplug/replug or open Device Manager.
        """
        trusted = self.whitelist.list_devices()
        if not trusted:
            return
        logger.info(
            f"Healing check: scanning {len(trusted)} whitelisted VID/PID pairs..."
        )
        for device in trusted:
            vid = device.get("vendor",  "")
            pid = device.get("product", "")
            if vid and pid:
                self._enable_by_vid_pid(vid, pid)


#  Entry point
if __name__ == "__main__":
    app = USBGuard()
    app.start()
