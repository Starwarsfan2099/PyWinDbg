@echo off
echo.
echo [92mBuilding PyWindDbg...[0m
echo.
pyinstaller ..\pywindbg.py -F --upx-dir %UPX_PATH% --distpath ..\Executables --console --workpath tmp --specpath spec
echo.
echo [92mDone![0m
echo.