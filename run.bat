@echo off
REM Double-click to launch Firestore Workbench (opens in your browser).
cd /d "%~dp0"
python firestore_workbench.py %*
pause
