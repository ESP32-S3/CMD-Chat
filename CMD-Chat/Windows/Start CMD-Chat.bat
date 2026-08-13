@echo off
setlocal
cd /d "%~dp0"

set "CMDCHAT_EXE="
if exist "Windows-x64-CMD-Chat.exe" set "CMDCHAT_EXE=Windows-x64-CMD-Chat.exe"
if not defined CMDCHAT_EXE if exist "CMD-Chat.exe" set "CMDCHAT_EXE=CMD-Chat.exe"
if not defined CMDCHAT_EXE if exist "cmd-chat.exe" set "CMDCHAT_EXE=cmd-chat.exe"

if not defined CMDCHAT_EXE (
    echo.
    echo Windows-x64-CMD-Chat.exe was not found.
    echo Make sure you extracted the complete CMD-Chat release ZIP.
    echo.
    pause
    exit /b 1
)

title CMD-Chat
"%~dp0%CMDCHAT_EXE%"

rem Hold the window open if CMD-Chat exited badly. Without this the terminal
rem closes the instant the process dies and takes the reason with it, which is
rem how a crash on "Start a chat" looked like the window closing by itself.
if errorlevel 1 (
    echo.
    echo CMD-Chat closed unexpectedly ^(exit code %errorlevel%^).
    echo.
    pause
)
exit /b %errorlevel%
