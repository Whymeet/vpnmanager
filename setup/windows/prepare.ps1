# Подготовка к установке appguard на Windows. Запускается БЕЗ прав
# администратора: её выполняет установка (setup\windows\install.ps1) первыми
# тремя шагами, а Claude Code может запустить её сам:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File setup\windows\prepare.ps1
#
# 1. Проверяет, что это Windows 10 или 11 и что у пользователя есть права
#    администратора. Права проверяются первыми: без них установка невозможна, и
#    скрипт останавливается, ничего не скачав и не собрав.
# 2. Находит Go не старше версии из go.mod. Если его нет — ставит Go в
#    .toolchain\ клона: без прав администратора и без изменений в системе,
#    удаляется вместе с клоном.
# 3. Собирает инструмент в bin\appguard.exe.
#
# С -ForInstall её запускает установка: шаги нумеруются из пяти, дальше служба.
# С -ForUpdate — «appguard update» из PowerShell от имени администратора; новую
# версию ставит сама команда.
#
# Файл в UTF-8 с BOM: без BOM Windows PowerShell 5.1 читает его в кодировке
# системы, и русские строки ломаются. $ErrorActionPreference не Stop: в 5.1 с
# ним любая строка программы в stderr обрывает скрипт — ошибки проверяются явно.

param([switch]$ForUpdate, [switch]$ForInstall)

[Console]::OutputEncoding = [Text.Encoding]::UTF8 # вывод читает и агент

$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Toolchain = Join-Path $Repo '.toolchain'

# Go, который ставится, если подходящего нет. Суммы — со страницы go.dev/dl.
$GoVersion = '1.27.2'
$GoSha256 = @{
  amd64 = '1314008898bd40df77af4b014f777f08873dbdfbcd3d92308728ee03304fe04f'
  arm64 = '5c4b294f23b558619ae8a4aa94d023e3bca03f52c8398bb41b9026002b0013de'
}

$script:Total = if ($ForInstall) { 5 } else { 3 }
$script:N = 0
function Section([string]$msg) { $script:N++; Write-Host ''; Write-Host "[$($script:N)/$($script:Total)] $msg" }
function Step([string]$msg) { Write-Host "  · $msg" }
function Ok([string]$msg) { Write-Host "  ✓ $msg" }
function Fail([string]$msg) { [Console]::Error.WriteLine("  ✗ $msg"); exit 1 }

# --- система и права ---------------------------------------------------------

Section 'Проверяю систему и права'
if ($env:OS -ne 'Windows_NT') { Fail 'Это не Windows: здесь подготовка не подходит.' }
$os = Get-CimInstance Win32_OperatingSystem
if (([Version]$os.Version).Major -lt 10) { Fail "Нужна Windows 10 или 11, а здесь $($os.Caption)." }

# Администратор без «Запуска от имени администратора» тоже администратор: группа
# S-1-5-32-544 есть в его маркере, хоть и только запрещающая. У обычного
# пользователя её нет вовсе. SID одинаков на любом языке Windows.
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
if (-not ((whoami /groups) -match 'S-1-5-32-544')) {
  Fail "У пользователя $user нет прав администратора, поэтому установить appguard нельзя. В системе ничего не изменено. Нужна учётная запись администратора: Параметры → Учётные записи."
}

# Сборка под родную архитектуру, даже если PowerShell запущен в эмуляции.
try { $osArch = [string][Runtime.InteropServices.RuntimeInformation]::OSArchitecture } catch { $osArch = $env:PROCESSOR_ARCHITECTURE }
switch -Regex ($osArch) {
  '^arm64$' { $arch = 'arm64' }
  '^(x64|amd64)$' { $arch = 'amd64' }
  default { Fail "Процессор $osArch не поддерживается: нужен x64 или ARM64." }
}
Ok "$($os.Caption) (сборка $($os.BuildNumber)), $arch, пользователь $user — администратор"

# --- Go ----------------------------------------------------------------------

Section 'Ищу Go для сборки'
$need = (Select-String -Path (Join-Path $Repo 'go.mod') -Pattern '^go (\S+)').Matches[0].Groups[1].Value

# GoVersionOf печатает версию Go по пути $go (1.27.2) или ничего. GOTOOLCHAIN=local
# и запуск не из клона не дают go.mod клона скачать другой тулчейн при проверке.
function GoVersionOf([string]$go) {
  if (-not $go -or -not (Test-Path $go)) { return $null }
  $env:GOTOOLCHAIN = 'local'
  Push-Location ([IO.Path]::GetTempPath())
  try { $v = & $go env GOVERSION 2>$null } catch { $v = $null } finally { Pop-Location }
  if ($v -match '^go(\d+\.\d+(\.\d+)?)') { return $Matches[1] }
  return $null
}

function FindGo {
  $candidates = @(
    (Join-Path $Toolchain 'go\bin\go.exe'),
    (Get-Command go -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source),
    (Join-Path $env:ProgramFiles 'Go\bin\go.exe')
  )
  foreach ($g in $candidates) {
    $v = GoVersionOf $g
    if ($v -and ([Version]$v -ge [Version]$need)) { return $g }
  }
  return $null
}

function InstallGo {
  Step "Go $need+ не найден — скачиваю Go $GoVersion (около 80 МБ) в ${Toolchain}: он нужен только для сборки, права администратора не нужны"
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ('appguard-go-' + [Guid]::NewGuid())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    $zip = Join-Path $tmp 'go.zip'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue' # с полосой прогресса 5.1 качает в разы медленнее
    # go.dev отдаёт файл с dl.google.com, а из России он часто не открывается —
    # тогда зеркало. Подмену с зеркала ловит контрольная сумма ниже.
    $file = "go$GoVersion.windows-$arch.zip"
    $urls = @("https://go.dev/dl/$file", "https://mirrors.aliyun.com/golang/$file")
    $errors = @()
    $got = $false
    foreach ($url in $urls) {
      try {
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip -ErrorAction Stop
        $got = $true
        break
      } catch {
        $errors += "    $url — $($_.Exception.Message)"
        Step "Не скачалось с $url, пробую следующий адрес"
        Remove-Item -Force $zip -ErrorAction SilentlyContinue
      }
    }
    if (-not $got) {
      Fail ("Не удалось скачать Go. Причины:`n" + ($errors -join "`n") + "`n  Включи VPN в режиме TUN (полный туннель, не «системный прокси») и запусти установку ещё раз.")
    }
    if ((Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower() -ne $GoSha256[$arch]) {
      Fail 'Контрольная сумма Go не сошлась: файл повреждён или подменён. Ничего не установлено.'
    }
    Step 'Контрольная сумма сошлась, распаковываю'
    # tar.exe есть в Windows 10 с 1803 и распаковывает zip в разы быстрее .NET.
    # Но в части сборок Windows 11 он не читает имена файлов не из ASCII
    # («Archive entry has empty or unreadable filename») — тогда .NET ZipFile:
    # имена в UTF-8 он понимает. Expand-Archive не берём: с ним 5.1 в разы
    # медленнее из-за полосы прогресса.
    $unpacked = $false
    $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
    if (Test-Path $tar) {
      & $tar -xf $zip -C $tmp 2>$null
      if ($LASTEXITCODE -eq 0) {
        $unpacked = $true
      } else {
        Step 'tar.exe не справился, распаковываю средствами .NET (это чуть дольше)'
        Remove-Item -Recurse -Force (Join-Path $tmp 'go') -ErrorAction SilentlyContinue
      }
    }
    if (-not $unpacked) {
      try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $tmp)
      } catch { Fail "Не удалось распаковать Go: $($_.Exception.Message)" }
    }
    New-Item -ItemType Directory -Force -Path $Toolchain | Out-Null
    $dst = Join-Path $Toolchain 'go'
    if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
    try { Move-Item -Path (Join-Path $tmp 'go') -Destination $dst -ErrorAction Stop } catch { Fail "Не удалось положить Go в ${dst}: $_" }
  } finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}

$Go = FindGo
if (-not $Go) {
  InstallGo
  $Go = FindGo
  if (-not $Go) { Fail "Go поставлен, но не запускается: $Toolchain\go\bin\go.exe." }
}
Ok "go$(GoVersionOf $Go): $Go"

# --- сборка ------------------------------------------------------------------

# Всё нужное для сборки лежит в клоне (vendor\), так что сеть не нужна.
# GOENV=off — чужие настройки Go пользователя не влияют на сборку; CGO_ENABLED=0 —
# не нужен компилятор C. -trimpath — в файл не попадают пути клона.
Section 'Собираю appguard'
if (-not (Test-Path (Join-Path $Toolchain 'cache'))) { Step 'Первая сборка занимает пару минут, следующие — секунды' }
$exe = Join-Path $Repo 'bin\appguard.exe'
New-Item -ItemType Directory -Force -Path (Join-Path $Repo 'bin') | Out-Null
$env:GOENV = 'off'
$env:GOTOOLCHAIN = 'local'
$env:GOFLAGS = '-mod=vendor'
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = $arch
$env:GOPATH = Join-Path $Toolchain 'gopath'
$env:GOCACHE = Join-Path $Toolchain 'cache'
# appguardw.exe — тот же appguard без окна консоли: задачи планировщика
# (уведомления, обновление каталога) запускают его, и окна не мигают.
$quietExe = Join-Path $Repo 'bin\appguardw.exe'
Push-Location $Repo
try {
  & $Go build -trimpath '-ldflags=-s -w' -o $exe ./cmd/appguard
  if ($LASTEXITCODE -eq 0) { & $Go build -trimpath '-ldflags=-s -w -H=windowsgui' -o $quietExe ./cmd/appguard }
} finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { Fail 'Сборка не прошла — вывод выше. В системе ничего не изменено.' }
$built = & $exe version
if ($LASTEXITCODE -ne 0) { Fail 'Собранный bin\appguard.exe не запускается.' }

Ok "appguard $built — $exe и appguardw.exe"

if ($ForUpdate -or $ForInstall) { exit 0 }

$install = Join-Path $Repo 'setup\windows\install.ps1'
Write-Host ''
Write-Host 'В системе пока ничего не изменено. Установка — в обычном окне PowerShell:'
Write-Host ''
Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File `"$install`""
Write-Host ''
Write-Host 'Она повторит эти шаги за секунды и поставит службу; Windows один раз спросит разрешение.'
