@echo off
REM One-command verification for the isolation release drill.
REM Prefers the Python 3.12 py launcher; falls back to python on PATH.
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py -3.12 "%~dp0run_all.py" %*
) else (
    python "%~dp0run_all.py" %*
)
exit /b %ERRORLEVEL%
