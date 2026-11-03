@echo off
REM Database backup for Windows / XAMPP. Reads MYSQL_* from ..\.env and writes backups\<db>_<timestamp>.sql
REM Schedule it nightly with Task Scheduler (see DEPLOY.md). Copy the backups folder OFF this PC regularly.
setlocal EnableDelayedExpansion
cd /d "%~dp0.."
set "MYSQLDUMP=C:\xampp\mysql\bin\mysqldump.exe"
if not exist "%MYSQLDUMP%" (echo mysqldump not found at %MYSQLDUMP% - edit this file & exit /b 1)
set "DB_HOST=127.0.0.1" & set "DB_PORT=3306" & set "DB_NAME=" & set "DB_USER=" & set "DB_PASS="
for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
  if /i "%%A"=="MYSQL_HOST" set "DB_HOST=%%B"
  if /i "%%A"=="MYSQL_PORT" set "DB_PORT=%%B"
  if /i "%%A"=="MYSQL_DATABASE" set "DB_NAME=%%B"
  if /i "%%A"=="MYSQL_USER" set "DB_USER=%%B"
  if /i "%%A"=="MYSQL_PASSWORD" set "DB_PASS=%%B"
)
if "%DB_NAME%"=="" (echo MYSQL_DATABASE not found in .env & exit /b 1)
if not exist backups mkdir backups
for /f %%T in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "STAMP=%%T"
set "OUT=backups\%DB_NAME%_%STAMP%.sql"
set "MYSQL_PWD=%DB_PASS%"
"%MYSQLDUMP%" --host=%DB_HOST% --port=%DB_PORT% --user=%DB_USER% --single-transaction --routines --default-character-set=utf8mb4 --result-file="%OUT%" %DB_NAME%
if errorlevel 1 (echo BACKUP FAILED & exit /b 1)
forfiles /p backups /m *.sql /d -14 /c "cmd /c del @path" >nul 2>&1
echo Backup OK: %OUT%
