"""
USB Guard - Behavioural Sandbox Module
Installs WH_KEYBOARD_LL hook to intercept and analyse keystroke timing.
"""
import ctypes
import ctypes.wintypes
import time
import math
import threading
import logging
from collections import deque

logger = logging.getLogger(__name__)

WH_KEYBOARD_LL      = 13
WM_KEYDOWN          = 0x0100
WM_KEYUP            = 0x0101
ANALYSIS_WINDOW_MS  = 500
EXTENSION_WINDOW_MS = 500
MIN_KEYSTROKES      = 10

MODIFIERS = {0x10, 0x11, 0x12, 0x5B, 0x5C}  # Shift, Ctrl, Alt, Win L/R


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode",      ctypes.wintypes.DWORD),
        ("scanCode",    ctypes.wintypes.DWORD),
        ("flags",       ctypes.wintypes.DWORD),
        ("time",        ctypes.wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]


class BehaviouralSandbox:
    """
    Intercepts keystrokes via WH_KEYBOARD_LL for ANALYSIS_WINDOW_MS
    and extracts 6 timing features for ML classification.
    """

    def __init__(self):
        self._hook      = None
        self._callback  = None
        self._events    = deque()
        self._lock      = threading.Lock()
        self._capturing = False

    def analyse(self) -> dict:
        self._events.clear()
        self._capturing = True
        self._install_hook()

        # WH_KEYBOARD_LL callbacks are delivered only when the installing
        # thread pumps its Windows message queue — time.sleep() does not do
        # this, so PeekMessageW must be called in a tight loop instead.
        self._pump_messages(ANALYSIS_WINDOW_MS / 1000)

        with self._lock:
            count = sum(1 for _, t, _ in self._events if t == "down")

        if count < MIN_KEYSTROKES:
            logger.info("< 10 keystrokes in window — extending 500ms.")
            self._pump_messages(EXTENSION_WINDOW_MS / 1000)

        self._capturing = False
        self._uninstall_hook()

        features = self._extract_features()
        logger.info(f"Features: ikd_mean={features['ikd_mean']}ms  "
                    f"burst={features['burst_rate']}  "
                    f"entropy={features['entropy']}")
        return features

    def _pump_messages(self, duration_sec: float):
        """Drive the Windows message loop so hook callbacks are delivered."""
        msg = ctypes.wintypes.MSG()
        deadline = time.perf_counter() + duration_sec
        while time.perf_counter() < deadline:
            while ctypes.windll.user32.PeekMessageW(
                ctypes.byref(msg), None, 0, 0, 1
            ):
                ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
                ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))
            time.sleep(0.001)

    def _install_hook(self):
        try:
            HOOKPROC = ctypes.WINFUNCTYPE(
                ctypes.c_int, ctypes.c_int,
                ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM
            )
            self._callback = HOOKPROC(self._hook_proc)
            self._hook = ctypes.windll.user32.SetWindowsHookExW(
                WH_KEYBOARD_LL, self._callback, None, 0
            )
            logger.debug("WH_KEYBOARD_LL installed.")
        except Exception as e:
            logger.error(f"Hook install failed: {e}")

    def _uninstall_hook(self):
        try:
            if self._hook:
                ctypes.windll.user32.UnhookWindowsHookEx(self._hook)
                self._hook = None
            logger.debug("WH_KEYBOARD_LL removed.")
        except Exception as e:
            logger.error(f"Hook uninstall failed: {e}")

    def _hook_proc(self, nCode, wParam, lParam):
        if nCode >= 0 and self._capturing:
            try:
                kb = ctypes.cast(
                    lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)
                ).contents
                ts         = time.perf_counter_ns()
                event_type = "down" if wParam == WM_KEYDOWN else "up"
                with self._lock:
                    self._events.append((ts, event_type, kb.vkCode))
            except Exception:
                pass
        return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)

    def _extract_features(self) -> dict:
        with self._lock:
            events = list(self._events)

        if not events:
            return self._zero_features()

        down_ts  = [ts for ts, t, _ in events if t == "down"]
        up_map   = {}
        for ts, t, vk in events:
            if t == "up" and vk not in up_map:
                up_map[vk] = ts
        down_vks = [(ts, vk) for ts, t, vk in events if t == "down"]

        if len(down_ts) < 2:
            return self._zero_features()

        # Inter-keystroke delays (nanoseconds → milliseconds)
        ikds = [
            (down_ts[i+1] - down_ts[i]) / 1_000_000
            for i in range(len(down_ts) - 1)
        ]

        # Key-down durations
        durations = [
            (up_map[vk] - ts) / 1_000_000
            for ts, vk in down_vks
            if vk in up_map
        ]

        # Max burst in any 100ms window
        burst = self._burst_rate(down_ts, 100)

        # Modifier key usage flag
        mod_vks        = [vk for _, t, vk in events if t == "down" and vk in MODIFIERS]
        modifier_flag  = 1 if mod_vks else 0

        # Shannon entropy of keystroke sequence
        vk_sequence    = [vk for _, t, vk in events if t == "down"]
        entropy        = self._entropy(vk_sequence)

        return {
            "ikd_mean":      round(sum(ikds) / len(ikds), 3),
            "ikd_std":       round(self._std(ikds), 3),
            "keydown_dur":   round(sum(durations) / len(durations), 3)
                             if durations else 0.0,
            "burst_rate":    burst,
            "modifier_flag": modifier_flag,
            "entropy":       round(entropy, 3),
        }

    def _burst_rate(self, timestamps_ns: list, window_ms: int) -> int:
        if not timestamps_ns:
            return 0
        window_ns = window_ms * 1_000_000
        return max(
            sum(1 for t2 in timestamps_ns if t <= t2 < t + window_ns)
            for t in timestamps_ns
        )

    def _std(self, values: list) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return math.sqrt(
            sum((x - mean) ** 2 for x in values) / len(values)
        )

    def _entropy(self, vk_list: list) -> float:
        if not vk_list:
            return 0.0
        from collections import Counter
        counts = Counter(vk_list)
        total  = len(vk_list)
        return -sum(
            (c / total) * math.log2(c / total)
            for c in counts.values()
        )

    def _zero_features(self) -> dict:
        return {
            "ikd_mean": 0.0, "ikd_std": 0.0, "keydown_dur": 0.0,
            "burst_rate": 0, "modifier_flag": 0, "entropy": 0.0
        }
