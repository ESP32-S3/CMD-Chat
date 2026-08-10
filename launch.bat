@echo off
setlocal
cd /d "%~dp0"
if exist "bin\cmd-chat.exe" (
    start "CMD-Chat" cmd /k ""%~dp0bin\cmd-chat.exe""
    exit /b 0
)
if exist "cmd-chat.exe" (
    start "CMD-Chat" cmd /k ""%~dp0cmd-chat.exe""
    exit /b 0
)
echo CMD-Chat executable was not found.
echo Expected: bin\cmd-chat.exe or cmd-chat.exe
pause
