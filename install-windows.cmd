@echo off
rem Windows installer: runs setup\windows\install.ps1 (UAC is asked once).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\windows\install.ps1" %*
set "code=%errorlevel%"
setlocal EnableDelayedExpansion
if not "!cmdcmdline:/c =!"=="!cmdcmdline!" pause
exit /b %code%
