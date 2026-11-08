package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpnlock/internal/apps"
	"vpnlock/internal/cli"
	"vpnlock/internal/service/servicetest"
)

// withConfig — служба с администратором, приложение Notion и команда claude в
// PATH, конфиг в своей папке.
func withConfig(t *testing.T, conf string) (*servicetest.Service, cli.Env, string) {
	t.Helper()
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	s.DNS.Maps("claude.ai", "160.79.104.20")
	s.DNS.Maps("anthropic.com", "160.79.104.21")
	installed := []apps.App{{ID: "notion.id", Name: "Notion", Path: servicetest.App(t, t.TempDir(), "Notion", "notion.id")}}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	dir := t.TempDir()
	file := filepath.Join(dir, "my.conf")
	if err := os.WriteFile(file, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return s, cli.Env{Layout: s.Layout, Home: t.TempDir(), Installed: func() []apps.App { return installed }}, file
}

// Конфиг применяется по строке теми же командами, что набрал бы человек;
// чего нет на компьютере, пропускается; повторный запуск ничего не ломает.
func TestApplyConfig(t *testing.T) {
	_, env, file := withConfig(t, `# мой конфиг
app claude
app Notion
app Figma
app ~/Applications/Нет.app
protect claude.ai 160.79.104.10
import list.txt
exit Германия 203.0.113.7
notifications off
`)
	os.WriteFile(filepath.Join(filepath.Dir(file), "list.txt"), []byte("anthropic.com\n"), 0o644)

	r := vpnlock(env, "", "apply", file)
	for _, want := range []string{
		"Применяю конфиг " + file,
		"  · vpnlock add claude",
		"      claude добавлено и ждёт обучения",
		"      Notion добавлено и ждёт обучения",
		"  ! Figma — нет на этом компьютере, пропускаю",
		"  ! ~/Applications/Нет.app — нет на этом компьютере, пропускаю",
		"  · vpnlock protect claude.ai 160.79.104.10",
		"      Сервис claude.ai защищён",
		"      Адрес 160.79.104.10 защищён",
		"  · vpnlock import " + filepath.Join(filepath.Dir(file), "list.txt"),
		"      Защищено сразу: 1 домен",
		"  · vpnlock remember Германия 203.0.113.7",
		"      Запомнено: Германия — введён вручную",
		"      Уведомления: выключены.",
		"  Служба: работает с ",
		"  Вручную: anthropic.com, claude.ai; 1 адрес",
		"✓ Готово. Пропущено: 2 программы",
		"Чтобы сервисы открывались только через твои выходы: vpnlock rule mine",
	} {
		if !strings.Contains(r.out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if r.code != 0 || t.Failed() {
		t.Fatalf("%+v", r)
	}

	r = vpnlock(env, "", "apply", file)
	if r.code != 0 || strings.Count(r.out, "уже в списке — ждёт обучения") != 2 || !strings.Contains(r.out, "✓ Готово.") {
		t.Fatalf("повторно: %+v", r)
	}
}

// Ошибка в файле — отказ до изменений; неудача строки — остановка: правило
// «только мои» не включается, если выход до него не запомнился.
func TestApplyStopsBeforeHalfApplying(t *testing.T) {
	_, env, file := withConfig(t, "app Notion\nrule maybe\n")
	r := vpnlock(env, "", "apply", file)
	if r.code != 1 || !strings.Contains(r.err, "строка 2: нужно rule mine или rule any. Ничего не изменено.") || strings.Contains(r.out, "Notion") {
		t.Fatalf("%+v", r)
	}
	if r := vpnlock(env, "", "status"); !strings.Contains(r.out, "Приложения: пока ни одного") {
		t.Fatalf("после отказа: %s", r.out)
	}

	os.WriteFile(file, []byte("exit Офис 192.168.0.1\nrule mine\n"), 0o644)
	r = vpnlock(env, "", "apply", file)
	if r.code != 1 || !strings.Contains(r.out, "не адрес выхода") || !strings.Contains(r.err, "Строка 1 не применена") || strings.Contains(r.out, "vpnlock rule") {
		t.Fatalf("%+v", r)
	}
	if r := vpnlock(env, "", "status"); !strings.Contains(r.out, "Правило: любой выход не из России") {
		t.Fatalf("правило сменилось: %s", r.out)
	}
}

// Без файла — конфиг этой системы из клона; выходов нет — подсказка, как
// добавить свои.
func TestApplyTakesThisSystemConfigFromTheClone(t *testing.T) {
	_, env, _ := withConfig(t, "")
	clone := t.TempDir()
	os.WriteFile(filepath.Join(clone, "go.mod"), []byte("module vpnlock\n"), 0o644)
	os.MkdirAll(filepath.Join(clone, "setup"), 0o755)
	t.Chdir(clone)

	r := vpnlock(env, "", "apply")
	if r.code != 1 || !strings.Contains(r.err, "В клоне нет конфига для этой системы: "+filepath.Join(clone, "configs", "macos.conf")) {
		t.Fatalf("без конфига: %+v", r)
	}
	os.MkdirAll(filepath.Join(clone, "configs"), 0o755)
	os.WriteFile(filepath.Join(clone, "configs", "linux.conf"), []byte("app nosuch\n"), 0o644)
	os.WriteFile(filepath.Join(clone, "configs", "macos.conf"), []byte("app claude\nnotifications on\n"), 0o644)
	r = vpnlock(env, "", "apply")
	if r.code != 0 || !strings.Contains(r.out, "Применяю конфиг "+filepath.Join(clone, "configs", "macos.conf")) ||
		!strings.Contains(r.out, "claude добавлено") || !strings.Contains(r.out, "✓ Готово: конфиг применён.") ||
		!strings.Contains(r.out, "vpnlock remember <имя>") || !strings.Contains(r.out, "vpnlock rule mine") {
		t.Fatalf("%+v", r)
	}

	t.Chdir(t.TempDir())
	if r := vpnlock(env, "", "apply"); r.code != 1 || !strings.Contains(r.err, "Не нашёл клон vpnlock") {
		t.Fatalf("не из клона: %+v", r)
	}
}

// Под sudo — отказ: PATH и домашняя папка были бы чужими. Не администратор
// получает отказ один раз, а не на каждой строке.
func TestApplyRefusals(t *testing.T) {
	_, env, file := withConfig(t, "notifications off\n")
	env.Root = true
	if r := vpnlock(env, "", "apply", file); r.code != 1 || !strings.Contains(r.err, "Запусти без sudo") {
		t.Fatalf("под sudo: %+v", r)
	}

	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: false}})
	os.WriteFile(file, []byte("protect claude.ai\nnotifications off\n"), 0o644)
	r := vpnlock(cli.Env{Layout: s.Layout}, "", "apply", file)
	if r.code != 1 || strings.Count(r.out, "только администратор") != 1 || !strings.Contains(r.err, "Строка 1 не применена") {
		t.Fatalf("не администратор: %+v", r)
	}
	if r := vpnlock(cli.Env{Layout: s.Layout}, "", "apply", filepath.Join(filepath.Dir(file), "нет.conf")); r.code != 1 || !strings.Contains(r.err, "Конфиг не читается") {
		t.Fatalf("нет файла: %+v", r)
	}
}
