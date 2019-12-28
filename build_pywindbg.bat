@echo off
echo.
echo Building PyWindDbg...
echo.
pyinstaller pywindbg.py -F --upx-dir %UPX_PATH% --distpath Executables --console
echo.
echo Done!
echo.