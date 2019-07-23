@echo off
echo.
echo Building DLL...
echo.
cl.exe /D_USRDLL /D_WINDLL helloDLL.cpp /link /DLL /OUT:Executables\helloDLL.dll
echo.
echo Done!
echo.