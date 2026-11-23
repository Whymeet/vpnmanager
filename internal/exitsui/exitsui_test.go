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
