@echo off
title USB Guard - Build EXE
color 0A
echo.
echo  ================================================
echo    USB Guard v1.1  -  Build Single EXE
echo  ================================================
echo.

:: Check dotnet is available
where dotnet >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] dotnet not found. Install .NET 8 SDK from https://dot.net
    pause
    exit /b 1
)

echo [1/2] Publishing GUI as single self-contained EXE...
echo       (this may take 30-60 seconds on first run)
echo.

dotnet publish "%~dp0gui\USBGuard.UI\USBGuard.UI.csproj" ^
    -c Release ^
    -r win-x64 ^
    --self-contained true ^
    -p:PublishSingleFile=true ^
    -p:IncludeNativeLibrariesForSelfExtract=true ^
    -o "%~dp0" ^
    --nologo

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed. See output above.
    pause
    exit /b 1
)

echo.
echo [2/2] Done!
echo.
echo  USBGuard.exe has been placed in:
echo  %~dp0
echo.
echo  To run:  right-click USBGuard.exe ^> Run as administrator
echo           (or double-click — UAC will prompt automatically)
echo.
echo  Requirements:
echo    - Python 3 installed and on PATH
echo    - pip install -r requirements.txt  (run once)
echo    - training\train_model.py          (run once to build ML models)
echo.
pause
