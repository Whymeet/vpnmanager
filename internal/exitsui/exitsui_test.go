package exitsui

import (
	"bytes"
	"testing"
)

// Без BOM Windows PowerShell 5.1 читает файл в кодировке системы и ломает
// русские строки; команды appguard, которые вызывает окно, должны существовать.
func TestScript(t *testing.T) {
	if !bytes.HasPrefix(Script, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("exits.ps1 без BOM")
	}
	for _, s := range []string{"'status', '--json'", "'remember'", "'forget'", "'rule', 'mine'", "-Verb RunAs"} {
		if !bytes.Contains(Script, []byte(s)) {
			t.Errorf("в exits.ps1 нет %s", s)
		}
	}
}

// Start-Process с -WindowStyle Hidden кладёт SW_HIDE в STARTUPINFO, и первый
// ShowWindow процесса прячет форму: окно «Мои VPN» не появилось бы.
func TestScriptWindowVisible(t *testing.T) {
	if bytes.Contains(Script, []byte("-Verb RunAs -WindowStyle Hidden")) {
		t.Error("exits.ps1 перезапускает себя со спрятанным окном — форма не появится")
	}
}
