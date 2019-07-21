@echo off
echo.
echo Building bufferOverflow...
echo.
pyinstaller bufferOverflow.py -F --upx-dir C:\Users\Owner\Downloads\upx-3.95-win64\upx-3.95-win64 --distpath Executables
echo.
echo Done!
echo.