@echo off
title Launch Network Intrusion Detection Notebook
cd /d "%~dp0"
echo ========================================================
echo Starting Jupyter Notebook for Network Intrusion AI...
echo ========================================================
python -m notebook notebooks\Network_Intrusion_Detection.ipynb
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Jupyter Notebook exited with code %ERRORLEVEL%.
    pause
)
