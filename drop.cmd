@echo off
rem cmd.exe shim for drop.ps1 (same directory). Prefers pwsh, falls back to
rem Windows PowerShell. The child's exit code is passed through.
setlocal
set "PS=powershell"
where /q pwsh && set "PS=pwsh"
"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0drop.ps1" %*
exit /b %ERRORLEVEL%
