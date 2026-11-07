package tray

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Скрипт — текст внутри Go: опечатку в нём увидела бы только живая проверка.
func TestScriptCompiles(t *testing.T) {
	src := filepath.Join(t.TempDir(), "tray.js")
	if err := os.WriteFile(src, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/usr/bin/osacompile", "-l", "JavaScript", "-o", filepath.Join(t.TempDir(), "tray.scpt"), src).CombinedOutput()
	if err != nil {
		t.Fatalf("osacompile: %v: %s", err, out)
	}
	for _, want := range []string{
		"setActivationPolicy(1)", "lock.shield.fill", "setTemplate(true)", "vpnlock работает",
		"NSStatusItem Preferred Position vpnlock", "autosaveName = $('vpnlock')", // у часов, а не левее всех
	} {
		if !strings.Contains(script, want) {
			t.Errorf("в скрипте нет %q", want)
		}
	}
}
