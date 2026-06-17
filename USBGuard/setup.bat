@echo off
setlocal enabledelayedexpansion
title USB Guard - First-Time Setup
color 0A

echo.
echo  ============================================================
echo    USB Guard - First-Time Setup
echo    Run this once before launching USBGuard.exe
echo  ============================================================
echo.

:: ─────────────────────────────────────────────────────────────
:: STEP 0 — Require Administrator (auto-elevate if needed)
:: ─────────────────────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Administrator privileges required.
    echo      Re-launching as Administrator...
    echo.
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)
echo  [OK] Running as Administrator.
echo.


:: ─────────────────────────────────────────────────────────────
:: STEP 1 — Locate Python 3
:: ─────────────────────────────────────────────────────────────
echo [1/6] Checking for Python 3...

set PYTHON_CMD=
for %%C in (python py python3) do (
    if not defined PYTHON_CMD (
        %%C --version >nul 2>&1
        if !errorlevel! equ 0 (
            set PYTHON_CMD=%%C
        )
    )
)

if not defined PYTHON_CMD (
    echo.
    echo  [ERROR] Python 3 was not found on PATH.
    echo.
    echo  Fix:
    echo    1. Download Python 3.11 or later from https://python.org/downloads
    echo    2. During install, tick "Add Python to PATH"
    echo    3. Re-run this setup script
    echo.
    goto :fail
)

for /f "tokens=*" %%V in ('%PYTHON_CMD% --version 2^>^&1') do set PYVER=%%V
echo  [OK] %PYVER%  (command: %PYTHON_CMD%)
echo.


:: ─────────────────────────────────────────────────────────────
:: STEP 2 — Install Python dependencies
:: ─────────────────────────────────────────────────────────────
echo [2/6] Installing Python dependencies from requirements.txt...
echo       (first run may take 1-2 minutes)
echo.

%PYTHON_CMD% -m pip install --upgrade pip --quiet --no-warn-script-location
%PYTHON_CMD% -m pip install -r "%~dp0requirements.txt" --quiet --no-warn-script-location

if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] pip install failed.
    echo.
    echo  Possible causes:
    echo    - No internet connection
    echo    - Proxy/firewall blocking pip
    echo.
    echo  Try manually:
    echo    pip install -r requirements.txt
    echo.
    goto :fail
)
echo  [OK] Dependencies installed.
echo.


:: ─────────────────────────────────────────────────────────────
:: STEP 3 — Register pywin32 DLLs (critical for WMI + IPC pipe)
:: ─────────────────────────────────────────────────────────────
echo [3/6] Registering pywin32 DLLs...
echo       (needed for USB monitoring and GUI communication)
echo.

%PYTHON_CMD% -c ^
"import sys, os, subprocess; ^
script = os.path.join(sys.exec_prefix, 'Scripts', 'pywin32_postinstall.py'); ^
found = os.path.exists(script); ^
print('Script found:', script if found else 'NOT FOUND'); ^
exit(0 if found else 1)" >nul 2>&1

if %errorlevel% equ 0 (
    for /f "tokens=*" %%P in ('%PYTHON_CMD% -c "import sys,os; print(os.path.join(sys.exec_prefix,\"Scripts\",\"pywin32_postinstall.py\"))"') do set PW32_SCRIPT=%%P
    %PYTHON_CMD% "!PW32_SCRIPT!" -install -quiet >nul 2>&1
    echo  [OK] pywin32 DLLs registered.
) else (
    echo  [WARN] pywin32_postinstall.py not at expected location.
    echo         Trying fallback via pip wheel path...
    %PYTHON_CMD% -c ^
    "import subprocess,sys,site,os; ^
    paths = getattr(site,'getsitepackages',lambda:[])(); ^
    paths += [getattr(site,'getusersitepackages',lambda:'')()] if callable(getattr(site,'getusersitepackages',None)) else []; ^
    found=[]; ^
    [found.append(os.path.join(os.path.dirname(p),'Scripts','pywin32_postinstall.py')) for p in paths if os.path.exists(os.path.join(os.path.dirname(p),'Scripts','pywin32_postinstall.py'))]; ^
    subprocess.run([sys.executable, found[0], '-install', '-quiet']) if found else print('not found')" >nul 2>&1
    echo  [WARN] If WMI detection fails, run manually as admin:
    echo         python Scripts\pywin32_postinstall.py -install
)
echo.


:: ─────────────────────────────────────────────────────────────
:: STEP 4 — Verify critical imports
:: ─────────────────────────────────────────────────────────────
echo [4/6] Verifying imports...

set IMPORT_FAIL=0

%PYTHON_CMD% -c "import wmi" >nul 2>&1
if %errorlevel% neq 0 ( echo  [FAIL] wmi           & set IMPORT_FAIL=1 ) else ( echo  [OK]   wmi )

%PYTHON_CMD% -c "import pythoncom" >nul 2>&1
if %errorlevel% neq 0 ( echo  [FAIL] pythoncom      & set IMPORT_FAIL=1 ) else ( echo  [OK]   pythoncom )

%PYTHON_CMD% -c "import win32pipe, win32file" >nul 2>&1
if %errorlevel% neq 0 ( echo  [FAIL] win32pipe/file & set IMPORT_FAIL=1 ) else ( echo  [OK]   win32pipe / win32file )

%PYTHON_CMD% -c "import sklearn" >nul 2>&1
if %errorlevel% neq 0 ( echo  [FAIL] scikit-learn   & set IMPORT_FAIL=1 ) else ( echo  [OK]   scikit-learn )

%PYTHON_CMD% -c "import joblib" >nul 2>&1
if %errorlevel% neq 0 ( echo  [FAIL] joblib         & set IMPORT_FAIL=1 ) else ( echo  [OK]   joblib )

%PYTHON_CMD% -c "import Crypto" >nul 2>&1
if %errorlevel% neq 0 ( echo  [FAIL] pycryptodome   & set IMPORT_FAIL=1 ) else ( echo  [OK]   pycryptodome )

if %IMPORT_FAIL% equ 1 (
    echo.
    echo  [ERROR] One or more imports failed.
    echo.
    echo  Fix: re-run this script, or manually run:
    echo    pip install -r requirements.txt
    echo    python Scripts\pywin32_postinstall.py -install
    echo.
    goto :fail
)
echo.


:: ─────────────────────────────────────────────────────────────
:: STEP 5 — Databases and ML models
:: ─────────────────────────────────────────────────────────────
echo [5/6] Checking databases and ML models...

set DB_MISSING=0
set MODEL_MISSING=0

if not exist "%~dp0backend\data\whitelist.db"          set DB_MISSING=1
if not exist "%~dp0backend\data\audit_log.db"          set DB_MISSING=1
if not exist "%~dp0backend\data\malicious_profiles.db" set DB_MISSING=1

if not exist "%~dp0backend\models\rf_model_v1.pkl"     set MODEL_MISSING=1
if not exist "%~dp0backend\models\iso_model_v1.pkl"    set MODEL_MISSING=1

if %DB_MISSING% equ 1 (
    echo  Databases not found — running setup_database.py...
    pushd "%~dp0backend"
    %PYTHON_CMD% setup_database.py
    if !errorlevel! neq 0 (
        echo  [ERROR] Database setup failed. See output above.
        popd
        goto :fail
    )
    popd
    echo  [OK] Databases created.
) else (
    echo  [OK] Databases present.
)

if %MODEL_MISSING% equ 1 (
    echo  ML models not found — running train_model.py...
    echo  (this takes about 30 seconds)
    pushd "%~dp0training"
    %PYTHON_CMD% train_model.py
    if !errorlevel! neq 0 (
        echo  [ERROR] Model training failed. See output above.
        popd
        goto :fail
    )
    popd
    echo  [OK] ML models trained and saved.
) else (
    echo  [OK] ML models present.
)
echo.


:: ─────────────────────────────────────────────────────────────
:: STEP 6 — Final verification
:: ─────────────────────────────────────────────────────────────
echo [6/6] Running final verification...
echo.
pushd "%~dp0backend"
%PYTHON_CMD% verify_setup.py
set VERIFY_EXIT=%errorlevel%
popd

if %VERIFY_EXIT% neq 0 (
    echo.
    echo  [WARN] Verification reported issues (see above).
    echo         You may still be able to run the app.
)


:: ─────────────────────────────────────────────────────────────
:: Optional: libusb notice
:: ─────────────────────────────────────────────────────────────
echo.
%PYTHON_CMD% -c "import usb.core; usb.core.find()" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [NOTE] libusb is not installed.
    echo         USB descriptor class detection will use WMI fallback only.
    echo         For best detection accuracy, install libusb-win32:
    echo           https://github.com/mcuee/libusb-win32/releases
    echo         (optional — the app works without it)
    echo.
)


:: ─────────────────────────────────────────────────────────────
:: Done
:: ─────────────────────────────────────────────────────────────
echo  ============================================================
echo    Setup complete! USB Guard is ready to run.
echo.
echo    To launch:
echo      Right-click USBGuard.exe and choose
echo      "Run as administrator"
echo.
echo    IMPORTANT: Always run as Administrator.
echo    The app needs admin rights for:
echo      - USB port monitoring (WMI)
echo      - Keyboard behaviour analysis (WH_KEYBOARD_LL hook)
echo      - Blocking malicious devices (pnputil)
echo  ============================================================
echo.
pause
exit /b 0


:fail
echo.
echo  ============================================================
echo    Setup did NOT complete successfully.
echo    Fix the error shown above and re-run setup.bat.
echo  ============================================================
echo.
pause
exit /b 1
