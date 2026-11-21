package service_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"appguard/internal/apps"
	"appguard/internal/enforce"
	"appguard/internal/ipc"
	"appguard/internal/service/servicetest"
)

// Сценарии таски 35: консольная программа на macOS (Claude Code).

const (
	claudeLink = "/Users/me/.local/bin/claude"
	claudeDir  = "/Users/me/.local/share/claude/versions"
	claudeID   = apps.CommandPrefix + claudeDir
)

// withCommand — служба, которая узнаёт по пути claudeLink консольную программу.
func withCommand(t *testing.T) *servicetest.Service {
	t.Helper()
	return servicetest.Start(t, "", servicetest.Fakes{
		Accounts: &servicetest.Accounts{Admin: true},
		ReadApp: func(path string) (apps.App, error) {
			if path == claudeLink {
				return apps.App{ID: claudeID, Name: "claude", Path: claudeDir, Command: true}, nil
			}
			return apps.Read(path)
		},
	})
}

// Обученная программа учит только новые имена своих зарегистрированных
// доменов: сайт, который она открыла по просьбе человека, не закрывается вне
// VPN для всех программ, а его адрес не становится её адресом.
func TestCommandLearnsOnlyItsOwnSitesAfterLearning(t *testing.T) {
	s := withCommand(t)
	resp := addApp(t, s, claudeLink)
	if !resp.OK || resp.App == nil || !resp.App.Command || resp.App.Learned || resp.App.Name != "claude" {
		t.Fatalf("добавление: %+v", resp)
	}
	hasLine(t, s, "claude добавлено и ждёт обучения")
	hasLine(t, s, "не открывай через неё посторонние сайты")

	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, onePath("verified"))
	listening(t, s, "utun11")

	// Пока идёт обучение — всё, куда она ходит: API и сторонняя телеметрия.
	s.Answers.Say("utun11", "api.anthropic.com", "160.79.104.10")
	s.Answers.Say("utun11", "http-intake.logs.us5.datadoghq.com", "34.149.66.137")
	s.Apps.Run(claudeID, "160.79.104.10:443", "34.149.66.137:443")
	st := s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { a, _ := app(st, claudeID); return a.Learned })
	if a, _ := app(st, claudeID); a.Addrs != 2 || a.Domains != 2 {
		t.Fatalf("обученная программа: %+v", a)
	}
	hasLine(t, s, "claude защищено: обучение закончено, 2 адреса, 2 домена")

	// Обучена. Документация, открытая по просьбе человека, — не её; новое имя
	// её зарегистрированного домена — её.
	s.Answers.Say("utun11", "docs.python.org", "151.101.0.223")
	s.Answers.Say("utun11", "statsig.anthropic.com", "160.79.104.20")
	s.Apps.Run(claudeID, "160.79.104.10:443", "34.149.66.137:443", "151.101.0.223:443", "160.79.104.20:443")
	deadline := time.Now().Add(2 * time.Second)
	for !slices.Contains(s.SystemDNS.Domains(), "statsig.anthropic.com") {
		if time.Now().After(deadline) {
			t.Fatalf("новое имя своего домена не выучено: %v", s.SystemDNS.Domains())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := s.SystemDNS.Domains(); slices.Contains(got, "docs.python.org") {
		t.Fatalf("чужой сайт стал доменом программы: %v", got)
	}
	if r := s.Enforce.Rules(); has(r, "151.101.0.223") || has(r, "160.79.104.20") {
		t.Fatalf("после обучения адреса не учатся: %+v", r)
	}
	if a, _ := app(s.Status(t), claudeID); a.Addrs != 2 || a.Domains != 3 {
		t.Fatalf("после обучения: %+v", a)
	}

	// Выгрузка пишет имя команды, а не путь из домашней папки автора.
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdExport})
	if err != nil || !resp.OK || len(resp.Learned) != 1 {
		t.Fatalf("выгрузка: %v %+v", err, resp)
	}
	l := resp.Learned[0]
	if l.Command != "claude" || l.ID != "" || strings.Contains(l.Name+l.ID, "/Users") ||
		!slices.Contains(l.Domains, "statsig.anthropic.com") || slices.Contains(l.Domains, "docs.python.org") {
		t.Fatalf("выгрузка: %+v", l)
	}
}

// Консольная программа из каталога защищена сразу — по имени команды.
func TestCommandFromCatalogIsProtectedAtOnce(t *testing.T) {
	s := withCommand(t)
	s.DNS.Maps("anthropic.com", "160.79.104.10")
	if resp := s.LoadCatalog(t, `{"format": 1, "updated": "2026-10-16", "apps": [
		{"name": "Claude Code", "macos": {"command": "claude"}, "domains": ["anthropic.com"]}]}`); !resp.OK {
		t.Fatalf("каталог: %+v", resp)
	}
	resp := addApp(t, s, claudeLink)
	if !resp.OK || !resp.App.Learned || !resp.App.Catalog {
		t.Fatalf("программа из каталога не защищена сразу: %+v", resp)
	}
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return len(r.OpenIfaces) == 0 && has(r, "160.79.104.10") })
	if got := s.SystemDNS.Domains(); !slices.Equal(got, []string{"anthropic.com"}) {
		t.Fatalf("на службу направлены %v", got)
	}
}
