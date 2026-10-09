@echo off
title Push Network Intrusion Detection AI to GitHub
echo ========================================================
echo Pushing Network Intrusion Detection AI to GitHub...
echo ========================================================
cd /d "%~dp0"
git push -u origin main
echo.
if %errorlevel% equ 0 (
    echo ========================================================
    echo SUCCESS! Your project is live on GitHub:
    echo https://github.com/Salmanali9675/network-intrusion-detection-ai
    echo ========================================================
) else (
    echo ========================================================
    echo If repository was not found on GitHub:
    echo 1. Create 'network-intrusion-detection-ai' at:
    echo    https://github.com/new
    echo    (Leave 'Initialize this repository with README' UNCHECKED)
    echo 2. Run this script again!
    echo ========================================================
)
pause
