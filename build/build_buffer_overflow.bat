@echo off
echo.
echo [92mBuilding bufferOverflow...[0m
echo.
pyinstaller ..\bufferOverflow.py -F --upx-dir %UPX_PATH% --distpath ..\Executables --workpath tmp --specpath spec
echo.
echo [92mDone![0m
echo.