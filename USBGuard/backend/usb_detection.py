"""
USB Guard - USB Detection Module
Subscribes to WMI USB insertion events and captures device descriptors.
"""
import re
import threading
import time
import logging

logger = logging.getLogger(__name__)

try:
    import wmi
    import pythoncom
    WINDOWS_MODE = True
except ImportError:
    WINDOWS_MODE = False
    logger.warning("WMI not available — running in simulation mode.")

# PyUSB is optional: provides extended descriptor info but requires libusb.
# Detection still works without it using WMI PnP data.
try:
    import usb.core
    import usb.util
    PYUSB_AVAILABLE = True
except ImportError:
    PYUSB_AVAILABLE = False
    logger.warning("PyUSB not available — descriptor class info will be limited.")

# Regex to extract VID/PID from Windows PnP DeviceID strings like
# USB\VID_046D&PID_C52B\... or HID\VID_046D&PID_C52B&MI_00\...
_VID_RE = re.compile(r'VID_([0-9A-Fa-f]{4})', re.IGNORECASE)
_PID_RE = re.compile(r'PID_([0-9A-Fa-f]{4})', re.IGNORECASE)


class USBDetectionModule:
    """
    Listens for USB insertion events via WMI (Win32_PnPEntity) and builds
    a device descriptor from WMI data + optional PyUSB extended info.
    """

    DESCRIPTOR_READ_DELAY_MS = 100
    DEDUP_WINDOW_SEC         = 2.0

    def __init__(self, on_device_connected):
        self.on_device_connected = on_device_connected
        self._seen    = {}
        self._running = False

    def start(self):
        self._running = True
        t = threading.Thread(target=self._listen, daemon=True)
        t.start()
        logger.info("USB Detection Module started.")

    def stop(self):
        self._running = False

    def _listen(self):
        if WINDOWS_MODE:
            self._listen_wmi()
        else:
            self._listen_simulation()

    def _listen_wmi(self):
        pythoncom.CoInitialize()
        c = wmi.WMI()
        # Win32_PnPEntity fires for all Plug-and-Play device arrivals.
        # Win32_USBHub only fires for hub nodes — keyboards, mice, and
        # Rubber Ducky devices are leaf devices and never trigger it.
        watcher = c.Win32_PnPEntity.watch_for("creation")
        while self._running:
            try:
                event = watcher(timeout_ms=1000)
                if event:
                    device_id = getattr(event, "DeviceID", "") or ""
                    # Keep only USB devices that carry a VID/PID pair.
                    # Root hubs (USB\ROOT_HUB...) have no VID_ and are skipped.
                    if "VID_" not in device_id.upper():
                        continue
                    # Skip MI_ (Multi-Interface) child nodes of composite USB
                    # devices.  A Logitech mouse creates:
                    #   USB\VID_046D&PID_C52B          ← process this one
                    #   HID\VID_046D&PID_C52B&MI_00    ← mouse function, skip
                    #   HID\VID_046D&PID_C52B&MI_01    ← keyboard function, skip
                    # Single-function HID devices (Rubber Ducky, plain USB
                    # keyboards) have no &MI_ and are still processed normally.
                    if "&MI_" in device_id.upper():
                        logger.debug(f"Skipping composite HID interface: {device_id}")
                        continue
                    self._handle_event(event)
            except Exception as e:
                if self._running:
                    # COM error 0x80041032 (WBEM_E_TIMED_OUT / -2147209215) is
                    # raised every poll cycle when no USB event arrives — normal.
                    if "-2147209215" not in str(e):
                        logger.warning(f"WMI event error: {e}")

    def _listen_simulation(self):
        logger.info("Simulation mode active — no real USB events.")
        while self._running:
            time.sleep(1)

    def _handle_event(self, event):
        device_id = getattr(event, "DeviceID", "unknown")
        now = time.time()

        # Prune stale dedup entries to prevent unbounded growth
        cutoff = now - self.DEDUP_WINDOW_SEC * 10
        self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

        # Deduplication — Windows 11 fires multiple PnP events per device
        if device_id in self._seen:
            if now - self._seen[device_id] < self.DEDUP_WINDOW_SEC:
                return
        self._seen[device_id] = now

        time.sleep(self.DESCRIPTOR_READ_DELAY_MS / 1000)

        descriptor = self._read_descriptor(event)
        if descriptor:
            self.on_device_connected(descriptor)

    def _read_descriptor(self, event):
        try:
            device_id = getattr(event, "DeviceID", "") or ""

            # VID and PID live inside the DeviceID string — WMI event objects
            # do NOT expose standalone VendorID / ProductID attributes.
            vid_m = _VID_RE.search(device_id)
            pid_m = _PID_RE.search(device_id)
            if not vid_m or not pid_m:
                return None  # Not a standard USB device

            vid = int(vid_m.group(1), 16)
            pid = int(pid_m.group(1), 16)

            # WMI provides basic name/manufacturer info without libusb
            manufacturer = getattr(event, "Manufacturer", "") or ""
            product_name = getattr(event, "Name", "")        or "Unknown Device"
            device_class    = 0
            device_subclass = 0
            device_protocol = 0

            # HID devices appear with a HID\ prefix in DeviceID — use that
            # to infer device class when PyUSB isn't available.
            if device_id.upper().startswith("HID\\"):
                device_class    = 0x03   # HID
                device_protocol = 0x01   # Keyboard (conservative; refined below)

            # Attempt PyUSB for precise descriptor fields (requires libusb)
            if PYUSB_AVAILABLE:
                try:
                    dev = usb.core.find(idVendor=vid, idProduct=pid)
                    if dev is not None:
                        device_class    = dev.bDeviceClass
                        device_subclass = dev.bDeviceSubClass
                        device_protocol = dev.bDeviceProtocol
                        s = self._get_string(dev, dev.iManufacturer)
                        if s: manufacturer = s
                        s = self._get_string(dev, dev.iProduct)
                        if s: product_name = s
                except Exception:
                    pass  # libusb not installed; WMI fallback already set

            return {
                "idVendor":        f"0x{vid:04x}",
                "idProduct":       f"0x{pid:04x}",
                "bDeviceClass":    device_class,
                "bDeviceSubClass": device_subclass,
                "bDeviceProtocol": device_protocol,
                "iManufacturer":   manufacturer,
                "iProduct":        product_name,
                "device_id":       device_id,
            }
        except Exception as e:
            logger.error(f"Descriptor read failed: {e}")
            return None

    def _get_string(self, device, index):
        try:
            return usb.util.get_string(device, index) if index else ""
        except Exception:
            return ""
