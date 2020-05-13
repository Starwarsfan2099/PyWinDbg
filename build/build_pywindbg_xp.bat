@echo off
echo.
echo [92mInstalling proper Psutil for XP...[0m
echo.
pip install psutil==3.4.2
echo.
echo [92mBuilding PyWindDbg...[0m
echo.
pyinstaller ..\pywindbg.py -F --upx-dir %UPX_PATH% --distpath ..\Executables --console -n pywindbg_xp --workpath tmp --specpath spec
echo.
echo [92mReinstalling latest Psutil...[0m
echo.
pip install --upgrade psutil
echo.
echo [92mDone![0m
echo.