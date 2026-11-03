@echo off
REM Starts HawkEye with the Waitress production server (Windows).
REM Run it from anywhere; it switches to the project folder. Use NSSM or Task Scheduler to start it at boot (see DEPLOY.md).
cd /d "%~dp0.."
if not exist logs mkdir logs
call .venv\Scripts\activate.bat
:loop
waitress-serve --listen=127.0.0.1:8000 --threads=8 wsgi:app
echo [%date% %time%] server stopped, restarting in 5 seconds... >> logs\restarts.log
timeout /t 5 /nobreak >nul
goto loop
