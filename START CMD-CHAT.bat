@echo off
setlocal
cd /d "%~dp0"

if exist "bin\cmd-chat.exe" (
    start "CMD-Chat" cmd /k "bin\cmd-chat.exe"
    exit /b 0
)

if exist "cmd-chat.exe" (
    start "CMD-Chat" cmd /k "cmd-chat.exe"
    exit /b 0
)

if exist "bin\cmd-chat" (
    start "CMD-Chat" cmd /k "bin\cmd-chat"
    exit /b 0
)

if exist "cmd-chat" (
    start "CMD-Chat" cmd /k "cmd-chat"
    exit /b 0
)

echo.
echo CMD-Chat has not been built yet.
echo.
echo If you downloaded the source code, open docs\QUICKSTART.md.
echo If you downloaded a release, make sure the CMD-Chat executable is next to this launcher.
echo.
pause
