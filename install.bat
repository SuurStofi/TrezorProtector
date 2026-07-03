@echo off
setlocal

echo =============================================
echo  TrezorProtector — Windows Setup
echo =============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.  Install from https://python.org
    pause & exit /b 1
)

echo [1/3] Installing Python dependencies...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] pip install failed.
    pause & exit /b 1
)

echo [2/3] Verifying trezorlib...
python -c "import trezorlib; print('  trezorlib OK')"
if errorlevel 1 (
    echo [ERROR] trezorlib could not be imported.
    pause & exit /b 1
)

echo [3/3] Verifying cryptography...
python -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('  cryptography OK')"

echo.
echo =============================================
echo  Setup complete!
echo.
echo  NOTE (Windows USB):
echo    Trezor One uses a HID driver.
echo    If the device is not detected, run Zadig
echo    (https://zadig.akeo.ie) and install the
echo    WinUSB or libusb-win32 driver for your
echo    Trezor device.
echo.
echo  Quick start:
echo    python main.py init
echo    python main.py --help
echo =============================================
echo.
pause
