@echo off
setlocal EnableExtensions

set "ROOT_DIR=%~dp0"
if "%ROOT_DIR:~-1%"=="\" set "ROOT_DIR=%ROOT_DIR:~0,-1%"
cd /d "%ROOT_DIR%"

set "PYTHON=python"
set "MODE=%~1"
if "%MODE%"=="" set "MODE=once"
set "SLEEP_SECONDS=%~2"
if "%SLEEP_SECONDS%"=="" set "SLEEP_SECONDS=900"

set "LOG_DIR=%ROOT_DIR%\demo_logs"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

where %PYTHON% >nul 2>&1
if errorlevel 1 (
  echo [ERR] Python not found in PATH.
  exit /b 1
)

echo [INFO] Root=%ROOT_DIR%
echo [INFO] Mode=%MODE%

goto :main

:run_once
echo [INFO] %DATE% %TIME% Running collect
%PYTHON% pipeline.py --phase collect
if errorlevel 1 exit /b 1

echo [INFO] %DATE% %TIME% Running process
%PYTHON% pipeline.py --phase process
if errorlevel 1 exit /b 1

echo [INFO] %DATE% %TIME% Running analyze
%PYTHON% pipeline.py --phase analyze
if errorlevel 1 exit /b 1

exit /b 0

:main
if /I "%MODE%"=="once" (
  call :run_once
  exit /b %errorlevel%
)

if /I "%MODE%"=="loop" (
  :loop_start
  call :run_once
  echo [INFO] Cycle complete. Sleeping %SLEEP_SECONDS%s before next run.
  timeout /t %SLEEP_SECONDS% /nobreak >nul
  goto :loop_start
)

echo [ERR] Unsupported mode. Use:
echo   auto_run_windows.bat once
echo   auto_run_windows.bat loop 900
exit /b 1
