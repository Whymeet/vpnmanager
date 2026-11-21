package main

import (
	"path/filepath"

	"appguard/internal/cli"
	"appguard/internal/dnswatch"
	"appguard/internal/enforce"
	"appguard/internal/install"
	"appguard/internal/paths"
	"appguard/internal/service"
)

// setupDir — папка установочных скриптов этой системы в клоне.
const setupDir = "macos"

func installer(L paths.Layout) *install.Installer {
	return &install.Installer{Layout: L, Launchd: install.Launchctl{}, Agent: sudoAgent(), Legacy: legacy(L)}
}

// enforcer — исполнитель правил с токеном включения pf в каталоге службы.
func enforcer(L paths.Layout) enforce.Enforcer {
	return &enforce.PF{TokenFile: filepath.Join(L.StateDir, "pf.token")}
}

func answers() service.Answers { return dnswatch.System{} }

// ready — launchd не ждёт от службы готовности.
func ready() {}

// alive — на macOS за службой следит launchd, сторожа systemd здесь нет.
func alive() {}

func installNote(note string) string { return note }

func platformCLI(*cli.Env) {}
