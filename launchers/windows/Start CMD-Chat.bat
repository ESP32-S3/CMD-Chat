@echo off
setlocal
cd /d "%~dp0"

if not exist "CMD-Chat.exe" (
    echo.
    echo CMD-Chat.exe was not found.
    echo Make sure you extracted the entire CMD-Chat ZIP.
    echo.
    pause
    exit /b 1
)

title CMD-Chat
"%~dp0CMD-Chat.exe"
