@echo off
setlocal
cd /d "%~dp0"
if exist "CMD-Chat.exe" (
    start "" "CMD-Chat.exe"
    exit /b 0
)
if exist "..\..\bin\cmd-chat.exe" (
    start "" "..\..\bin\cmd-chat.exe"
    exit /b 0
)
echo CMD-Chat.exe was not found.
echo If you downloaded the source code, run scripts\install.py first.
pause
