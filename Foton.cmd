# Foton.cmd — double-click or run from Explorer. Forwards to tools\Invoke-FotonEasy.ps1
@echo off
setlocal
set "ROOT=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%tools\Invoke-FotonEasy.ps1" %*
exit /b %ERRORLEVEL%
