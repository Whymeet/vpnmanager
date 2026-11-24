package cli

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// HideWindow кладёт SW_HIDE в STARTUPINFO: первый ShowWindow PowerShell взял бы
// его, и форма «Мои VPN» осталась бы невидимой, а установка ждала бы её вечно.
func TestVPNWindowNotHidden(t *testing.T) {
	ui := filepath.Join(t.TempDir(), "exits.ps1")
	if err := os.WriteFile(ui, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var env Env
	env.Layout.ExitsUI = ui
	cmd, err := vpnCommand(env)
	if err != nil {
		t.Fatal(err)
	}
	if a := cmd.SysProcAttr; a == nil || a.HideWindow || a.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("SysProcAttr = %+v: нужен CREATE_NO_WINDOW без HideWindow", a)
	}
}
