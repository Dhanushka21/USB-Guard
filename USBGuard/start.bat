@echo off
title USB Guard Launcher
color 0A
echo.
echo  ================================================
echo    USB Guard v1.0  -  Ducky Detection System
echo  ================================================
echo.

echo [1/2] Starting Python detection backend...
start "USB Guard Backend" cmd /k "cd /d %~dp0backend && python main.py"

echo Waiting for backend to initialise (3 seconds)...
timeout /t 3 /nobreak >nul

echo [2/2] Launching C# GUI...
start "USB Guard GUI" cmd /k "cd /d %~dp0gui\USBGuard.UI && dotnet run"

echo.
echo  USB Guard is now running.
echo  Close both terminal windows to stop.
echo.
pause
