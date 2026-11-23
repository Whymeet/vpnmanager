:; exec bash "$(dirname "$0")/setup/install.sh" "$@"
@echo off
rem Installer: sh runs setup/install.sh, cmd.exe runs setup\windows\install.ps1. LF only.
rem

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\windows\install.ps1" %*
set "code=%errorlevel%"

setlocal EnableDelayedExpansion
if not "!cmdcmdline:/c =!"=="!cmdcmdline!" pause
exit /b %code%
