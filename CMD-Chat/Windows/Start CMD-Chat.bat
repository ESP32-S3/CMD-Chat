@echo off
setlocal
cd /d "%~dp0"

if not exist "Windows-x64-CMD-Chat.exe" (
    echo.
    echo Windows-x64-CMD-Chat.exe was not found.
    echo Make sure you extracted the complete CMD-Chat release ZIP.
    echo.
    pause
    exit /b 1
)

title CMD-Chat
"%~dp0Windows-x64-CMD-Chat.exe"
