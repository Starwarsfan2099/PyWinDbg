@echo off
echo.
echo Building bufferOverflow...
echo.
pyinstaller bufferOverflow.py -F --upx-dir %UPX_PATH% --distpath Executables
echo.
echo Done!
echo.