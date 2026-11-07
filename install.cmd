:; exec bash "$(dirname "$0")/setup/install.sh" "$@"
@echo off
rem Установка vpnlock одним файлом на все системы.
rem   macOS:   ./install.cmd в Терминале
rem   Linux:   ./install.cmd в терминале
rem   Windows: двойной щелчок в Проводнике или .\install.cmd в PowerShell
rem
rem Первую строку sh выполняет (двоеточие у него пустая команда) и уходит в
rem setup/install.sh, дальше он не читает. cmd.exe считает её меткой и
rem пропускает, а дальше запускает setup\windows\install.ps1: ключ Bypass
rem нужен, иначе Windows не даёт запускать сценарии PowerShell. Права
rem администратора install.ps1 попросит сам.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\windows\install.ps1" %*
set "code=%errorlevel%"

rem Запуск двойным щелчком (cmd.exe /c) закрыл бы окно сразу с итогом.
setlocal EnableDelayedExpansion
if not "!cmdcmdline:/c =!"=="!cmdcmdline!" pause
exit /b %code%
