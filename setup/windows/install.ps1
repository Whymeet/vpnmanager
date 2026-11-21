# Установка appguard на Windows — одной командой из клона, в обычном окне
# PowerShell:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File setup\windows\install.ps1
#
# Идёт по шагам и пишет, что делает: система и права, Go, сборка (это
# подготовка, prepare.ps1 — без прав администратора), служба, проверка. На шаге
# «служба» Windows один раз спрашивает разрешение: установка идёт в окне
# администратора (-Elevated), а её вывод возвращается сюда через файл (-Log) —
# Start-Process -Verb RunAs вывод не перенаправляет. Запущенный уже от имени
# администратора скрипт ставит службу сразу. Повторный запуск обновляет
# установку, настройки сохраняются.
#
# Claude Code его не запускает (блок правил в setup/README.md). Файл в UTF-8 с
# BOM — иначе Windows PowerShell 5.1 ломает русские строки.

param([switch]$Elevated, [string]$Log)

[Console]::OutputEncoding = [Text.Encoding]::UTF8

$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Exe = Join-Path $Repo 'bin\appguard.exe'
$Self = Join-Path $Repo 'setup\windows\install.ps1'

function Section([int]$n, [string]$msg) { Write-Host ''; Write-Host "[$n/5] $msg" }
function Step([string]$msg) { Write-Host "  · $msg" }
function Fail([string]$msg) { [Console]::Error.WriteLine("  ✗ $msg"); exit 1 }

if ($env:OS -ne 'Windows_NT') { Fail 'Это не Windows: здесь установка не подходит.' }

# Окно администратора с шага 4: ставит службу и оставляет вывод для исходного
# окна. Строки ошибок программы приходят записями ошибок — в файл идёт их текст.
if ($Elevated) {
  Write-Host 'Ставлю службу appguard — окно закроется само.'
  & $Exe install 2>&1 | ForEach-Object { "$_" } | Tee-Object -Variable lines | Out-Host
  $code = $LASTEXITCODE
  if ($Log) { $lines | Set-Content -Encoding UTF8 -Path $Log }
  exit $code
}

Write-Host "Установка appguard на этот компьютер. Клон: $Repo"

& (Join-Path $Repo 'setup\windows\prepare.ps1') -ForInstall
if ($LASTEXITCODE -ne 0) { exit 1 }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin) {
  Section 4 'Ставлю службу'
  & $Exe install 2>&1 | ForEach-Object { Write-Host "  $_" }
  $code = $LASTEXITCODE
} else {
  Section 4 'Ставлю службу — Windows спросит разрешение'
  Step 'На вопрос «Разрешить этому приложению вносить изменения?» ответь «Да». Откроется окно установки и закроется само.'
  $logFile = Join-Path ([IO.Path]::GetTempPath()) ('appguard-install-' + [Guid]::NewGuid() + '.log')
  try {
    $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ErrorAction Stop -ArgumentList @(
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$Self`"", '-Elevated', '-Log', "`"$logFile`"")
  } catch {
    Fail "Windows не дал прав администратора — служба не поставлена, в системе ничего не изменено. Запусти установку ещё раз и ответь «Да»: powershell -NoProfile -ExecutionPolicy Bypass -File `"$Self`""
  }
  if (Test-Path $logFile) {
    Get-Content -Encoding UTF8 -Path $logFile | ForEach-Object { Write-Host "  $_" }
    Remove-Item -Force $logFile -ErrorAction SilentlyContinue
  }
  $code = $p.ExitCode
}
if ($code -ne 0) {
  Fail "Служба не поставлена — причина выше. Исправь её и запусти установку ещё раз: powershell -NoProfile -ExecutionPolicy Bypass -File `"$Self`""
}

Section 5 'Проверяю службу'
& $Exe status 2>&1 | ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) { Fail 'Служба не отвечает. Причина — в C:\ProgramData\appguard\logs\daemon.log.' }

Write-Host ''
Write-Host '✓ Готово: appguard установлен и стартует вместе с Windows.'
Write-Host ''
Write-Host 'Дальше — в новом окне PowerShell от имени администратора (меню «Пуск» → «PowerShell»,'
Write-Host 'правой кнопкой — «Запуск от имени администратора»): в открытых окнах команды appguard ещё нет.'
Write-Host '  appguard apply            программы и сервисы из готового конфига (configs\windows.conf)'
Write-Host '  appguard remember <имя>   свой выход VPN: подключи VPN и запомни; повтори для каждого'
Write-Host '  appguard rule mine        сервисы открыты только через твои выходы'
Write-Host '  appguard                  меню: добавить приложение, правило, проверка'
