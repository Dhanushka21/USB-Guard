"""
USB Guard - IPC Named Pipe Server (FIXED)
Broadcasts real-time JSON events to the C# GUI client.
"""
import json
import threading
import time
import logging

logger = logging.getLogger(__name__)

PIPE_NAME   = r"\\.\pipe\USBGuardIPC"
BUFFER_SIZE = 65536

try:
    import win32pipe
    import win32file
    import win32event
    import pywintypes
    WINDOWS_MODE = True
except ImportError:
    WINDOWS_MODE = False
    logger.warning("win32pipe not available — IPC disabled.")


class IPCServer:

    def __init__(self):
        self._pipe      = None
        self._lock      = threading.Lock()
        self._running   = False
        self._connected = threading.Event()

    def start(self):
        self._running = True
        if WINDOWS_MODE:
            t = threading.Thread(target=self._serve, daemon=True)
            t.start()
            logger.info(f"IPC server started on {PIPE_NAME}")
        else:
            logger.info("IPC server skipped (non-Windows).")

    def stop(self):
        self._running = False
        self._connected.set()

    def send(self, event_type: str, payload: dict):
        if not WINDOWS_MODE:
            logger.debug(f"[IPC MOCK] {event_type}")
            return

        msg = json.dumps({"type": event_type, "payload": payload}) + "\n"
        encoded = msg.encode("utf-8")

        with self._lock:
            if self._pipe:
                try:
                    win32file.WriteFile(self._pipe, encoded)
                except pywintypes.error as e:
                    logger.warning(f"IPC write failed — client disconnected: {e}")
                    self._pipe = None
                    self._connected.clear()

    def _serve(self):
        while self._running:
            pipe = None
            try:
                # ── Create a DUPLEX pipe so we can detect disconnection ──
                pipe = win32pipe.CreateNamedPipe(
                    PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX,          # <-- FIXED: duplex
                    win32pipe.PIPE_TYPE_MESSAGE |
                    win32pipe.PIPE_READMODE_MESSAGE |
                    win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,    # <-- allow reconnects
                    BUFFER_SIZE,
                    BUFFER_SIZE,
                    0,
                    None
                )

                logger.info("IPC pipe created — waiting for GUI client...")
                win32pipe.ConnectNamedPipe(pipe, None)

                with self._lock:
                    self._pipe = pipe
                self._connected.set()
                logger.info("GUI client connected to IPC pipe.")

                # ── Hold connection open — detect disconnect via small read ──
                while self._running:
                    try:
                        # Non-blocking peek to check if client is still there
                        result = win32pipe.PeekNamedPipe(pipe, 0)
                        # If we get here the pipe is still alive
                        time.sleep(0.5)
                    except pywintypes.error:
                        # Client disconnected
                        break

            except pywintypes.error as e:
                if self._running:
                    logger.error(f"IPC pipe error: {e}")
                    time.sleep(1)
            finally:
                with self._lock:
                    self._pipe = None
                self._connected.clear()
                if pipe:
                    try:
                        win32pipe.DisconnectNamedPipe(pipe)
                    except Exception:
                        pass
                    try:
                        win32file.CloseHandle(pipe)
                    except Exception:
                        pass
                if self._running:
                    logger.info("GUI client disconnected — waiting for reconnect...")