@echo off
echo.
echo Building PyWindDbg...
echo.
pyinstaller pywindbg.py -F --upx-dir C:\Users\Starw\Downloads\upx-3.95-win64\upx-3.95-win64  --distpath Executables --console
echo.
echo Done!
echo.