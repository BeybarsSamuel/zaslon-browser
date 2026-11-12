@echo off
chcp 65001 >nul
title Zaslon Browser - GitHub Kurulum Sihirbazi
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Zaslon-Setup-GitHub.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Kurulum bir hata ile sonlandi (Kod: %ERRORLEVEL%).
    pause
)
