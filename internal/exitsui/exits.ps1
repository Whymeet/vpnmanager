# Окно «Мои VPN» — список выходов VPN, через которые открыт Claude.
# Установка кладёт его в Program Files\appguard\exits.ps1 (писать туда может только
# администратор), открывает его установка, пункт «Мои VPN…» в меню щита и команда
# `appguard vpn`. Без прав администратора окно перезапускает себя через UAC: менять
# список выходов служба разрешает только администратору.
#
# Всё делает appguard.exe рядом: status --json, remember, forget, rule mine.
# Файл в UTF-8 с BOM — иначе Windows PowerShell 5.1 ломает русские строки.

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  # Без -WindowStyle Hidden у Start-Process: SW_HIDE попал бы в STARTUPINFO, и
  # первый ShowWindow процесса спрятал бы форму. Консоль прячет сам PowerShell.
  try {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ErrorAction Stop -ArgumentList @(
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`"") | Out-Null
  } catch {}
  exit 0
}

[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

$Exe = Join-Path $PSScriptRoot 'bin\appguard.exe'
if (-not (Test-Path $Exe)) {
  $Exe = (Get-Command appguard.exe -ErrorAction SilentlyContinue).Source
}

function Invoke-Ag([string[]]$Arguments) {
  $lines = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" }
  [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($lines -join "`r`n").Trim() }
}

function Get-AgState {
  $r = Invoke-Ag @('status', '--json')
  if ($r.Code -ne 0) { return $null }
  try { return ($r.Text | ConvertFrom-Json) } catch { return $null }
}

# Текущий проверенный выход: путь маршрута по умолчанию, иначе единственный проверенный.
function Get-CurrentExit($st) {
  $verified = @(@($st.paths) | Where-Object { $_ -and $_.state -eq 'verified' })
  $def = @($verified | Where-Object { $_.default })
  if ($def.Count -gt 0) { return $def[0] }
  if ($verified.Count -eq 1) { return $verified[0] }
  return $null
}

function Show-Error([string]$text) {
  if (-not $text) { $text = 'Не получилось — служба appguard не ответила.' }
  [Windows.Forms.MessageBox]::Show($form, $text, 'Мои VPN', 'OK', 'Warning') | Out-Null
}

function Set-RuleMine($st) {
  if ($st -and $st.rule -ne 'mine') { Invoke-Ag @('rule', 'mine') | Out-Null }
}

# --- окно ---------------------------------------------------------------------

$font = New-Object Drawing.Font('Segoe UI', 10)
$bold = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)

$form = New-Object Windows.Forms.Form
$form.Text = 'Мои VPN — Claude только через VPN'
$form.Font = $font
$form.ClientSize = New-Object Drawing.Size(560, 520)
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.StartPosition = 'CenterScreen'
$form.TopMost = $true
$form.AutoScaleMode = 'Dpi'

function New-Label([string]$text, [int]$x, [int]$y, [int]$w, [int]$h) {
  $l = New-Object Windows.Forms.Label
  $l.Text = $text; $l.Location = New-Object Drawing.Point($x, $y); $l.Size = New-Object Drawing.Size($w, $h)
  $l
}

$intro = New-Label 'Claude (приложение, Cowork и сайт в браузере) работает только через VPN из этого списка. Без VPN или через другой VPN он не загрузится.' 16 12 528 44
$form.Controls.Add($intro)

# Сейчас
$grpNow = New-Object Windows.Forms.GroupBox
$grpNow.Text = 'Сейчас'
$grpNow.Location = New-Object Drawing.Point(16, 60); $grpNow.Size = New-Object Drawing.Size(528, 96)
$lblNow = New-Label '…' 12 24 504 22
$lblClaude = New-Label '' 12 46 330 22
$lblClaude.Font = $bold
$btnAddNow = New-Object Windows.Forms.Button
$btnAddNow.Text = 'Добавить этот VPN'
$btnAddNow.Location = New-Object Drawing.Point(346, 50); $btnAddNow.Size = New-Object Drawing.Size(170, 34)
$grpNow.Controls.AddRange(@($lblNow, $lblClaude, $btnAddNow))
$form.Controls.Add($grpNow)

# Добавить по адресу
$grpAdd = New-Object Windows.Forms.GroupBox
$grpAdd.Text = 'Добавить VPN по адресу (не обязательно подключаться)'
$grpAdd.Location = New-Object Drawing.Point(16, 166); $grpAdd.Size = New-Object Drawing.Size(528, 110)
$grpAdd.Controls.Add((New-Label 'Название' 12 28 150 22))
$txtName = New-Object Windows.Forms.TextBox
$txtName.Location = New-Object Drawing.Point(12, 50); $txtName.Size = New-Object Drawing.Size(150, 26)
$grpAdd.Controls.Add((New-Label 'IP выхода (адрес, который видят сайты)' 172 28 340 22))
$txtIP = New-Object Windows.Forms.TextBox
$txtIP.Location = New-Object Drawing.Point(172, 50); $txtIP.Size = New-Object Drawing.Size(200, 26)
$btnAdd = New-Object Windows.Forms.Button
$btnAdd.Text = 'Добавить'
$btnAdd.Location = New-Object Drawing.Point(386, 47); $btnAdd.Size = New-Object Drawing.Size(130, 32)
$hint = New-Label 'Узнать IP: включи VPN и открой 1.1.1.1/cdn-cgi/trace — строка ip=' 12 82 504 22
$hint.ForeColor = [Drawing.Color]::DimGray
$grpAdd.Controls.AddRange(@($txtName, $txtIP, $btnAdd, $hint))
$form.Controls.Add($grpAdd)

# Список
$form.Controls.Add((New-Label 'Мои VPN' 16 286 300 22))
$list = New-Object Windows.Forms.ListView
$list.View = 'Details'; $list.FullRowSelect = $true; $list.MultiSelect = $false; $list.HideSelection = $false
$list.Location = New-Object Drawing.Point(16, 310); $list.Size = New-Object Drawing.Size(528, 150)
[void]$list.Columns.Add('Название', 200)
[void]$list.Columns.Add('IP', 190)
[void]$list.Columns.Add('Страна', 130)
$form.Controls.Add($list)

$btnDel = New-Object Windows.Forms.Button
$btnDel.Text = 'Удалить выбранный'
$btnDel.Location = New-Object Drawing.Point(16, 472); $btnDel.Size = New-Object Drawing.Size(180, 34)
$btnDel.Enabled = $false
$btnDone = New-Object Windows.Forms.Button
$btnDone.Text = 'Готово'
$btnDone.Location = New-Object Drawing.Point(424, 472); $btnDone.Size = New-Object Drawing.Size(120, 34)
$form.Controls.AddRange(@($btnDel, $btnDone))
$form.AcceptButton = $btnAdd
$form.CancelButton = $btnDone

$script:state = $null
$script:current = $null

function Update-View {
  $st = Get-AgState
  $script:state = $st
  if (-not $st) {
    $lblNow.Text = 'Служба appguard не отвечает — проверь, что она установлена.'
    $lblClaude.Text = ''; $btnAddNow.Enabled = $false
    return
  }
  $exits = @(@($st.exits) | Where-Object { $_ })
  $cur = Get-CurrentExit $st
  $script:current = $cur
  if ($cur) {
    $lblNow.Text = "VPN подключён: выход $($cur.ip) ($($cur.country)) — проверен"
    $known = @($exits | Where-Object { $_.ip -eq $cur.ip }).Count -gt 0
    if ($known) {
      $lblClaude.Text = 'Claude открыт ✓'; $lblClaude.ForeColor = [Drawing.Color]::ForestGreen
    } else {
      $lblClaude.Text = 'Claude закрыт: этого VPN нет в списке'; $lblClaude.ForeColor = [Drawing.Color]::Firebrick
    }
    $btnAddNow.Enabled = -not $known
  } else {
    $pending = @(@($st.paths) | Where-Object { $_ -and $_.state -eq 'pending' }).Count -gt 0
    $lblNow.Text = $(if ($pending) { 'VPN проверяется — подожди несколько секунд…' } else { 'VPN не подключён (или выход не прошёл проверку).' })
    $lblClaude.Text = 'Claude закрыт'; $lblClaude.ForeColor = [Drawing.Color]::Firebrick
    $btnAddNow.Enabled = $false
  }
  $selected = $null
  if ($list.SelectedItems.Count -gt 0) { $selected = $list.SelectedItems[0].SubItems[1].Text }
  $list.BeginUpdate()
  $list.Items.Clear()
  foreach ($x in $exits) {
    $country = $(if ($x.unverified) { 'ещё не проверен' } else { $x.country })
    $item = New-Object Windows.Forms.ListViewItem($x.name)
    [void]$item.SubItems.Add($x.ip)
    [void]$item.SubItems.Add($country)
    [void]$list.Items.Add($item)
    if ($x.ip -eq $selected) { $item.Selected = $true }
  }
  $list.EndUpdate()
  $btnDel.Enabled = $list.SelectedItems.Count -gt 0
}

function Get-FreeName([string]$base) {
  $names = @(@($script:state.exits) | Where-Object { $_ } | ForEach-Object { $_.name })
  if ($names -notcontains $base) { return $base }
  for ($i = 2; ; $i++) { if ($names -notcontains "$base $i") { return "$base $i" } }
}

$btnAddNow.Add_Click({
  $name = $txtName.Text.Trim()
  if (-not $name) { $name = Get-FreeName 'VPN' }
  $r = Invoke-Ag @('remember', $name)
  if ($r.Code -ne 0) { Show-Error $r.Text; return }
  Set-RuleMine $script:state
  $txtName.Text = ''
  Update-View
})

$btnAdd.Add_Click({
  $ipText = $txtIP.Text.Trim()
  $addr = $null
  if (-not $ipText -or -not [Net.IPAddress]::TryParse($ipText, [ref]$addr) -or ($ipText -notmatch '^[0-9a-fA-F:.]+$')) {
    Show-Error "«$ipText» — не IP-адрес. Пример: 203.0.113.5"
    $txtIP.Focus(); return
  }
  $name = $txtName.Text.Trim()
  if (-not $name) { $name = Get-FreeName 'VPN' }
  $r = Invoke-Ag @('remember', $name, $addr.ToString())
  if ($r.Code -ne 0) { Show-Error $r.Text; return }
  Set-RuleMine $script:state
  $txtName.Text = ''; $txtIP.Text = ''
  Update-View
})

$list.Add_SelectedIndexChanged({ $btnDel.Enabled = $list.SelectedItems.Count -gt 0 })

$btnDel.Add_Click({
  if ($list.SelectedItems.Count -eq 0) { return }
  $it = $list.SelectedItems[0]
  $ip = $it.SubItems[1].Text
  $left = $list.Items.Count - 1
  $msg = "Удалить VPN «$($it.Text)» ($ip)?"
  if ($left -eq 0) { $msg += "`r`n`r`nЭто последний VPN в списке — Claude будет закрыт при любом VPN, пока не добавишь новый." }
  if ([Windows.Forms.MessageBox]::Show($form, $msg, 'Мои VPN', 'YesNo', 'Question') -ne 'Yes') { return }
  $r = Invoke-Ag @('forget', $ip)
  if ($r.Code -ne 0) { Show-Error $r.Text }
  Update-View
})

$btnDone.Add_Click({ $form.Close() })

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 3000
$timer.Add_Tick({ Update-View })

$form.Add_Shown({
  Update-View
  $timer.Start()
  $form.Activate()
  $form.TopMost = $false
})
$form.Add_FormClosing({
  $timer.Stop()
  if ($script:state -and @(@($script:state.exits) | Where-Object { $_ }).Count -eq 0) {
    $answer = [Windows.Forms.MessageBox]::Show($form,
      "В списке нет ни одного VPN — Claude будет закрыт всегда.`r`n`r`nДобавить VPN потом: щит у часов → «Мои VPN…».`r`n`r`nЗакрыть окно?",
      'Мои VPN', 'YesNo', 'Warning')
    if ($answer -ne 'Yes') { $_.Cancel = $true; $timer.Start() }
  }
})

[void]$form.ShowDialog()
