package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// gitPath — git для Windows: из PATH, иначе там, куда его ставит установщик.
func gitPath() (string, error) {
	if p, err := exec.LookPath("git"); err == nil {
		return p, nil
	}
	if pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT); err == nil {
		p := filepath.Join(pf, "Git", "cmd", "git.exe")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("git не найден: поставь Git для Windows (winget install --id Git.Git)")
}

// quiet — git запускает задача из vpnlockw.exe, у которой нет консоли: без
// этого у каждого вызова git мелькало бы окно.
func quiet(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}
