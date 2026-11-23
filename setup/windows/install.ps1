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

# vpnmanager: после службы — свой конфиг (Claude и его сайты только через VPN) и
# окно «Мои VPN», всё в том же окне администратора, чтобы Windows спросила
# разрешение один раз.
$Config = 'configs\claude-vpn.conf'

[Console]::OutputEncoding = [Text.Encoding]::UTF8

$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Exe = Join-Path $Repo 'bin\appguard.exe'
$Self = Join-Path $Repo 'setup\windows\install.ps1'

function Section([int]$n, [string]$msg) { Write-Host ''; Write-Host "[$n/5] $msg" }
function Step([string]$msg) { Write-Host "  · $msg" }
function Fail([string]$msg) { [Console]::Error.WriteLine("  ✗ $msg"); exit 1 }

if ($env:OS -ne 'Windows_NT') { Fail 'Это не Windows: здесь установка не подходит.' }

# Служба, конфиг, окно «Мои VPN». Строки ошибок программы приходят записями
# ошибок — дальше идёт их текст.
function Install-All {
  & $Exe install 2>&1 | ForEach-Object { "$_" }
  if ($LASTEXITCODE -ne 0) { $script:code = $LASTEXITCODE; return }
  $installed = Join-Path $env:ProgramFiles 'appguard\bin\appguard.exe'
  ''
  'Включаю защиту Claude (конфиг ' + $Config + '):'
  & $installed apply (Join-Path $Repo $Config) 2>&1 | ForEach-Object { "$_" }
  if ($LASTEXITCODE -ne 0) { $script:code = $LASTEXITCODE; return }
  ''
  'Открываю окно «Мои VPN» — добавь свой VPN и нажми «Готово».'
  & $installed vpn 2>&1 | ForEach-Object { "$_" }
  $script:code = 0
}

# Окно администратора с шага 4: всё ставит и оставляет вывод для исходного окна.
if ($Elevated) {
  Write-Host 'Ставлю службу appguard — окно закроется само.'
  $script:code = 1
  Install-All | Tee-Object -Variable lines | Out-Host
  if ($Log) { $lines | Set-Content -Encoding UTF8 -Path $Log }
  exit $script:code
}

Write-Host "Установка appguard на этот компьютер. Клон: $Repo"

& (Join-Path $Repo 'setup\windows\prepare.ps1') -ForInstall
if ($LASTEXITCODE -ne 0) { exit 1 }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin) {
  Section 4 'Ставлю службу и включаю защиту Claude'
  $script:code = 1
  Install-All | ForEach-Object { Write-Host "  $_" }
  $code = $script:code
} else {
  Section 4 'Ставлю службу и включаю защиту Claude — Windows спросит разрешение'
  Step 'На вопрос «Разрешить этому приложению вносить изменения?» ответь «Да». Откроется окно установки, потом окно «Мои VPN».'
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
Write-Host '✓ Готово: защита стоит и включается сама вместе с Windows.'
Write-Host ''
Write-Host '  Claude (приложение, Cowork, сайт в браузере) работает только через VPN из списка «Мои VPN».'
Write-Host '  Щит у часов: с замком — Claude открыт, перечёркнутый — закрыт.'
Write-Host '  Изменить список VPN: щёлкни по щиту → «Мои VPN…».'
