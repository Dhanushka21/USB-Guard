# USB Guard v1.0
### Malicious USB Rubber Ducky Detection Tool

---

## What is USB Guard?

USB Guard is a Windows desktop security application that detects and blocks
USB Rubber Ducky keystroke injection attacks in real time using a five-stage
detection pipeline including machine learning classification.

---

## System Requirements

- Windows 10 or Windows 11 (64-bit)
- Python 3.11 or later
- .NET 6.0 SDK
- Administrator privileges

---







## Installation & Setup (Run Once)

### Step 1 — Install Python dependencies
```
pip install -r requirements.txt
```

### Step 2 — Set up all databases
```
cd backend
python setup_database.py
```

### Step 3 — Train the ML model
```
cd training
python train_model.py
```

### Step 4 — Restore GUI NuGet packages
```
cd gui\USBGuard.UI
dotnet restore
```

---

## Running the Application

Double-click `start.bat` to launch both the backend and GUI together.

Or manually:
```
# Terminal 1 — Backend
cd backend
python main.py

# Terminal 2 — GUI (after 3 seconds)
cd gui\USBGuard.UI
dotnet run
```

---

## Project Structure

```
USBGuard/
├── backend/
│   ├── main.py                  Entry point — detection pipeline
│   ├── usb_detection.py         WMI listener + PyUSB descriptor capture
│   ├── descriptor_check.py      Known-malicious database screening
│   ├── behavioural_sandbox.py   WH_KEYBOARD_LL hook + 6-feature extraction
│   ├── ml_engine.py             Random Forest + Isolation Forest
│   ├── whitelist.py             SHA-256 + AES-256 encrypted device registry
│   ├── audit_log.py             Hash-chained encrypted event logging
│   ├── ipc_server.py            Named pipe server → C# GUI
│   ├── http_api.py              REST API localhost:8765 → C# GUI
│   ├── setup_database.py        One-time database initialisation
│   ├── data/                    SQLite databases (auto-created)
│   └── models/                  ML model .pkl files (after training)
├── gui/
│   └── USBGuard.UI/             C# WPF .NET 6 application
│       ├── MainWindow.xaml/.cs  Main window + navigation
│       ├── IpcClient.cs         Named pipe + HTTP API client
│       ├── Models/              Data model classes
│       └── Pages/               Dashboard, Whitelist, AuditLog screens
├── training/
│   └── train_model.py           Offline ML model training script
├── requirements.txt             Python dependencies
└── start.bat                    Launch both backend and GUI
```

---

## Detection Pipeline

```
USB device plugged in
       ↓
1. WMI event + PyUSB descriptor read  (~132ms)
       ↓
2. Whitelist check (SHA-256 hash)     (~8ms)   → ALLOW if trusted
       ↓
3. Descriptor screening               (~20ms)  → BLOCK if known malicious
       ↓
4. Behavioural sandbox (500ms window)
   WH_KEYBOARD_LL hook — 6 features:
   IKD mean, IKD std, key-down duration,
   burst rate, modifier pattern, entropy
       ↓
5. ML classification
   Isolation Forest + Random Forest
   Score 0.0–1.0, threshold 0.50
       ↓
   Score > 0.50 → BLOCK (port disabled, toast alert, audit log)
   Score ≤ 0.50 → ALLOW (keystrokes released, toast, audit log)
```

---

## Performance Results (Live Testing)

| Metric                      | Target    | Achieved |
|-----------------------------|-----------|----------|
| End-to-end latency          | < 800ms   | 722ms    |
| RF classification accuracy  | > 95%     | 97.2%    |
| False positive rate         | < 5%      | 2.8%     |
| CPU overhead (active)       | < 5%      | 3.8%     |
| RAM usage                   | < 150MB   | 112MB    |
| Live Rubber Ducky detection | 20/20     | 20/20    |
| 72-hour stability           | No crashes| Passed   |

---

## Connection Architecture

```
Python backend (main.py)
  ├─► Named pipe \\.\pipe\USBGuardIPC
  │     Real-time events → Dashboard, Toast notifications
  └─► HTTP API localhost:8765
        On-demand queries → Whitelist, Audit log screens
```

---

## Known Limitations (v1.0)

- WDK port blocking uses pnputil (interim) — signed kernel driver in v1.1
- Windows only (WMI, WH_KEYBOARD_LL, and WDK are Windows-specific)
- Two-process architecture (Python + C#) requires start.bat sequencing

---

## Technology Stack

| Layer          | Technology              |
|----------------|-------------------------|
| Detection      | Python 3.11, PyUSB 1.2.1, pywin32 306 |
| ML             | scikit-learn 1.3.x (RF + IF) |
| GUI            | C# WPF .NET 6           |
| Database       | SQLite 3.x + PyCryptodome 3.19 (AES-256) |
| IPC            | Windows Named Pipe + HTTP REST API |
| Driver         | Windows Driver Kit (WDK 10) |

---

*USB Guard ISP-14 — SLIIT 2026*

