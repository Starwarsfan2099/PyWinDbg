@echo off
echo.
echo [92mBuilding DLL...[0m
echo.
cl.exe /D_USRDLL /D_WINDLL ..\helloDLL.cpp /link /DLL /OUT:..\Executables\helloDLL.dll
echo.
echo [92mDone![0m
echo.