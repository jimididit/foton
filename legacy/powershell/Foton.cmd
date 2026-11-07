@echo off
rem Forwards to tools\Invoke-FotonEasy.ps1 (double-click or run from Explorer).
setlocal
set "ROOT=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%tools\Invoke-FotonEasy.ps1" %*
exit /b %ERRORLEVEL%
