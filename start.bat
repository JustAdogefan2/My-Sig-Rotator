@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 app.py
  goto :eof
)
where python >nul 2>nul
if %errorlevel% equ 0 (
  python app.py
  goto :eof
)
echo Python 3 was not found.
echo Install it from https://www.python.org/downloads/ and enable "Add Python to PATH".
pause
