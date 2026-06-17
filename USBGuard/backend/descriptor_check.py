"""
USB Guard - Descriptor Screening Module
Checks device vendor/product IDs against malicious profiles database.
"""
import sqlite3
import os
import logging

logger = logging.getLogger(__name__)

DB_PATH      = os.path.join(os.path.dirname(__file__), "data", "malicious_profiles.db")
HID_CLASS    = 0x03
KBD_PROTOCOL = 0x01


class DescriptorChecker:

    def __init__(self):
        self._profiles = self._load_profiles()
        logger.info(f"Loaded {len(self._profiles)} malicious profiles from database.")

    def _load_profiles(self) -> set:
        try:
            with sqlite3.connect(DB_PATH) as conn:
                rows = conn.execute(
                    "SELECT vendor_id, product_id FROM malicious_profiles"
                ).fetchall()
            return {(r[0].lower(), r[1].lower()) for r in rows}
        except Exception as e:
            logger.error(f"Could not load malicious profiles DB: {e}")
            return set()

    def reload_profiles(self):
        self._profiles = self._load_profiles()
        logger.info(f"Profiles reloaded: {len(self._profiles)} entries.")

    def check(self, descriptor: dict) -> dict:
        vid             = descriptor.get("idVendor",       "").lower()
        pid             = descriptor.get("idProduct",      "").lower()
        device_class    = descriptor.get("bDeviceClass",    0)
        device_protocol = descriptor.get("bDeviceProtocol", 0)

        if (vid, pid) in self._profiles:
            logger.warning(f"Known malicious descriptor: {vid}:{pid}")
            return {"result": "BLOCK_IMMEDIATE",
                    "reason": "known_malicious_descriptor"}

        if device_class == HID_CLASS and device_protocol == KBD_PROTOCOL:
            logger.info(f"HID keyboard detected: {vid}:{pid}")
            return {"result": "ANALYSE", "reason": "hid_keyboard"}

        logger.info(f"Non-keyboard device: {vid}:{pid} — logged and allowed")
        return {"result": "ALLOW", "reason": "non_keyboard_device"}
