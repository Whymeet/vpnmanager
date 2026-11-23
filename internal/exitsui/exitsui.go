// Package exitsui — окно «Мои VPN» для Windows (PowerShell + WinForms): список
// выходов VPN, через которые открыты защищённые сервисы. Установка пишет его в
// папку программы (paths.Layout.ExitsUI), открывают его установка, пункт меню
// щита и `appguard vpn`.
package exitsui

import _ "embed"

// Script — exits.ps1 как есть, в UTF-8 с BOM.
//
//go:embed exits.ps1
var Script []byte
