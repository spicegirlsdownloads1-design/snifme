@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
title Trufflehog Intelligence v7.19.0 - Easy Start

:menu
cls
echo ==========================================================
echo       TRUFFLEHOG INTELLIGENCE v7.19.0 - EASY START
echo ==========================================================
echo.
echo   [1] Open Chrome extension setup / reload
echo   [2] Start guided local test page (requires Node.js)
echo   [3] Open the extension folder
echo   [4] Open Windows test checklist
echo   [5] Exit
echo.
choice /C 12345 /N /M "Choose 1-5: "
if errorlevel 5 goto done
if errorlevel 4 goto checklist
if errorlevel 3 goto folder
if errorlevel 2 goto test
if errorlevel 1 goto chrome_setup
goto menu

:chrome_setup
cls
echo FIRST-TIME INSTALLATION:
echo   1. On chrome://extensions enable Developer mode.
echo   2. Click Load unpacked.
echo   3. Select this folder (containing manifest.json):
echo      %~dp0
echo   4. For updates to an existing unpacked extension, click Reload.
echo   5. Approve site permissions only if you intend broad capture.
echo   6. Capture starts automatically on permitted sites.
echo      Use the popup switch to pause all-site capture.
echo.
call :open_chrome "chrome://extensions/"
echo.
pause
goto menu

:test
cls
where node >nul 2>&1
if errorlevel 1 (
  echo Node.js was not found on PATH.
  echo The Chrome extension does NOT need Node.js.
  echo Node.js is needed only for this optional local test page.
  echo Install Node.js, reopen this launcher, and retry option 2.
  echo.
  pause
  goto menu
)
if not exist "%~dp0local-test-server.txt" (
  echo The bundled local-test-server.txt is missing.
  pause
  goto menu
)
echo Starting the synthetic localhost server in another window.
echo Close that server window to stop the fixture.
echo No external services are contacted by the fixture.
start "Trufflehog Local Test - close to stop" /D "%~dp0" cmd /k node "local-test-server.txt"
timeout /T 2 /NOBREAK >nul
call :open_chrome "http://127.0.0.1:4317/"
echo.
echo Capture should start AUTOMATICALLY on localhost if it is not paused.
echo For product/licensing JSON: open F12 on the localhost page,
echo then run the tests. Response body analysis needs F12.
echo Follow the three steps on the guided test page.
echo Click Run all test requests, then open Dashboard ^> Capture diagnostics.
echo Verify IndexedDB journal and Uncompacted changes counters.
echo.
pause
goto menu

:folder
start "" explorer.exe "%~dp0"
goto menu

:checklist
start "" notepad.exe "%~dp0WINDOWS-CHROME-TEST-CHECKLIST.txt"
goto menu

:open_chrome
set "ChromeExe="
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set "ChromeExe=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if not defined ChromeExe if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set "ChromeExe=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
if not defined ChromeExe if exist "%LocalAppData%\Google\Chrome\Application\chrome.exe" set "ChromeExe=%LocalAppData%\Google\Chrome\Application\chrome.exe"
if not defined ChromeExe (
  echo Chrome was not found at the standard install locations.
  echo Open this address manually in Chrome: %~1
  exit /b 1
)
start "" "%ChromeExe%" "%~1"
exit /b 0

:done
endlocal
exit /b 0
