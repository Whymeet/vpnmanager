package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"appguard/internal/apps"
	"appguard/internal/cli"
	"appguard/internal/core"
	"appguard/internal/ipc"
	"appguard/internal/paths"
	"appguard/internal/service/servicetest"
)

type run struct {
	code     int
	out, err string
}

func appguard(env cli.Env, input string, args ...string) run {
	var out, errb bytes.Buffer
	env.In, env.Out, env.Err = strings.NewReader(input), &out, &errb
	if env.Version == "" {
		env.Version = servicetest.Version
	}
	code := cli.Run(args, env)
	return run{code, out.String(), errb.String()}
}

// emptyLayout — раскладка без установки.
func emptyLayout(t *testing.T) paths.Layout {
	L := paths.Under(t.TempDir())
	L.Socket = servicetest.Socket(t)
	return L
}

func TestStatusWithoutInstallation(t *testing.T) {
	r := appguard(cli.Env{Layout: emptyLayout(t)}, "", "status")
	if r.code != 1 || !strings.Contains(r.out, "не установлен") || !strings.Contains(r.out, "setup/README.md") {
		t.Fatalf("%+v", r)
	}
}

func TestStatusWhenServiceIsSilent(t *testing.T) {
	L := emptyLayout(t)
	os.MkdirAll(filepath.Dir(L.Plist), 0o755)
	os.WriteFile(L.Plist, []byte("plist"), 0o644)

	r := appguard(cli.Env{Layout: L}, "", "status")
	if r.code != 1 || !strings.Contains(r.out, "не отвечает — защита держится") || !strings.Contains(r.out, L.LogFile) {
		t.Fatalf("%+v", r)
	}
	// Меню над пунктами пишет то же.
	r = appguard(cli.Env{Layout: L, Interactive: true}, "\x1b[6~\r")
	if !strings.Contains(r.out, "служба не отвечает — защита держится") {
		t.Fatalf("меню: %+v", r)
	}
}

func TestStatusShowsRunningServiceAndVersion(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})

	r := appguard(cli.Env{Layout: s.Layout}, "", "status")
	if r.code != 0 || !strings.Contains(r.out, "Служба: работает с ") || !strings.Contains(r.out, "версия "+servicetest.Version) {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(r.out, "У этой команды версия") {
		t.Fatalf("версии совпадают, а статус пишет о разнице: %s", r.out)
	}

	r = appguard(cli.Env{Layout: s.Layout, Version: "10.0.0"}, "", "status")
	if !strings.Contains(r.out, "У этой команды версия 10.0.0") {
		t.Fatalf("статус не заметил, что команда другой версии: %s", r.out)
	}
}

func TestUninstallAsksForConfirmation(t *testing.T) {
	inst := &servicetest.Installation{}
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, Installation: inst})

	r := appguard(cli.Env{Layout: s.Layout}, "", "uninstall")
	if r.code != 1 || !strings.Contains(r.err, "подтвердить") {
		t.Fatalf("без терминала и --yes: %+v", r)
	}
	r = appguard(cli.Env{Layout: s.Layout, Interactive: true}, "нет\n", "uninstall")
	if r.code != 1 || !strings.Contains(r.out, "домашнего адреса") || !strings.Contains(r.out, "Отменено") {
		t.Fatalf("отказ от удаления: %+v", r)
	}
	r = appguard(cli.Env{Layout: s.Layout}, "", "uninstall", "Notion")
	if r.code != 2 {
		t.Fatalf("лишний аргумент: %+v", r)
	}
	if inst.Removed.Load() {
		t.Fatal("установка снята без подтверждения")
	}
}

func TestUninstallByNonAdminIsRefused(t *testing.T) {
	inst := &servicetest.Installation{}
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: false}, Installation: inst})

	r := appguard(cli.Env{Layout: s.Layout, Interactive: true}, "да\n", "uninstall")
	if r.code != 1 || !strings.Contains(r.err, "только администратор") || !strings.Contains(r.err, "student") {
		t.Fatalf("%+v", r)
	}
	if inst.Removed.Load() {
		t.Fatal("установка снята по команде не администратора")
	}
}

func TestUninstallByAdminWithoutSudo(t *testing.T) {
	inst := &servicetest.Installation{}
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, Installation: inst})

	r := appguard(cli.Env{Layout: s.Layout, Interactive: true}, "да\n", "uninstall")
	if r.code != 0 || !strings.Contains(r.out, "appguard удалён") {
		t.Fatalf("%+v", r)
	}
	if !inst.Removed.Load() || !inst.Stopped.Load() {
		t.Fatal("служба не сняла установку")
	}
	if strings.Contains(r.out, "ещё останавливается") {
		t.Fatalf("клиент не дождался остановки службы: %s", r.out)
	}
}

func TestUninstallWithSudoWorksWithoutService(t *testing.T) {
	L := emptyLayout(t)
	os.MkdirAll(L.AppDir, 0o755)
	removed := false

	r := appguard(cli.Env{Layout: L, Root: true, Uninstall: func() error { removed = true; return nil }}, "", "uninstall", "--yes")
	if r.code != 0 || !removed {
		t.Fatalf("%+v, снято: %v", r, removed)
	}

	r = appguard(cli.Env{Layout: L}, "", "uninstall", "--yes")
	if r.code != 1 || !strings.Contains(r.err, "sudo appguard uninstall") {
		t.Fatalf("без службы и без sudo: %+v", r)
	}
}

func TestInstallNeedsRoot(t *testing.T) {
	called := false
	r := appguard(cli.Env{Layout: emptyLayout(t), Install: func() (string, error) { called = true; return "", nil }}, "", "install")
	if r.code != 1 || called || !strings.Contains(r.err, "setup/macos/install.sh") || !strings.Contains(r.err, "ничего не изменено") {
		t.Fatalf("%+v, установка вызвана: %v", r, called)
	}
}

func TestUnknownCommand(t *testing.T) {
	r := appguard(cli.Env{Layout: emptyLayout(t)}, "", "пауза")
	if r.code != 2 || !strings.Contains(r.err, "Нет команды «пауза»") {
		t.Fatalf("%+v", r)
	}
}

func TestCommandsAreEnglishOnly(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	env := cli.Env{Layout: s.Layout}
	for _, args := range [][]string{{"статус"}, {"журнал"}, {"удалить", "--yes"}} {
		if r := appguard(env, "", args...); r.code != 2 || !strings.Contains(r.err, "Нет команды «"+args[0]+"»") {
			t.Fatalf("%v: %+v", args, r)
		}
	}
	for _, args := range [][]string{{"rule", "мои"}, {"notifications", "выкл"}, {"catalog", "загрузить"}} {
		if r := appguard(env, "", args...); r.code != 2 {
			t.Fatalf("%v: %+v", args, r)
		}
	}
	if r := appguard(env, "", "help"); !strings.Contains(r.out, "appguard rule [any|mine]") || strings.Contains(r.out, "appguard статус") {
		t.Fatalf("справка: %s", r.out)
	}
}

func TestStatusShowsVPN(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})
	if r := appguard(cli.Env{Layout: s.Layout}, "", "status"); !strings.Contains(r.out, "VPN: нет") {
		t.Fatalf("без туннелей: %s", r.out)
	}
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(servicetest.Tunnel("utun11", "10.8.1.1"))
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { return len(st.Paths) == 1 && st.Paths[0].State == "verified" })

	r := appguard(cli.Env{Layout: s.Layout}, "", "status")
	if !strings.Contains(r.out, "VPN: utun11 — выход 185.1.2.3, Германия — проверен") {
		t.Fatalf("%s", r.out)
	}
}

func TestCheckCommandReportsByItem(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, "Library/Application Support/Google/Chrome"), 0o755)
	os.WriteFile(filepath.Join(home, "Library/Application Support/Google/Chrome/Local State"),
		[]byte(`{"dns_over_https":{"mode":"secure","templates":"https://dns.google/dns-query"}}`), 0o644)

	r := appguard(cli.Env{Layout: s.Layout, Home: home}, "", "check")
	for _, want := range []string{
		"✓ Правила файрвола — на месте",
		"! Выход — VPN выключен",
		"✗ Chrome: безопасный DNS — включён свой (https://dns.google/dns-query)",
		"→ Настройки → Конфиденциальность и безопасность",
		"Итог: не в порядке — Chrome: безопасный DNS.",
	} {
		if !strings.Contains(r.out, want) {
			t.Fatalf("нет %q:\n%s", want, r.out)
		}
	}
	if r.code != 1 || strings.Contains(r.out, "всё в порядке") {
		t.Fatalf("%+v", r)
	}

	os.WriteFile(filepath.Join(home, "Library/Application Support/Google/Chrome/Local State"), []byte(`{}`), 0o644)
	if r := appguard(cli.Env{Layout: s.Layout, Home: home}, "", "check"); r.code != 0 || !strings.Contains(r.out, "Итог: всё в порядке.") {
		t.Fatalf("%+v", r)
	}
}

func TestNotificationsCommand(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	env := cli.Env{Layout: s.Layout}
	if r := appguard(env, "", "notifications"); r.code != 0 || !strings.Contains(r.out, "Уведомления: включены.") {
		t.Fatalf("%+v", r)
	}
	if r := appguard(env, "", "notifications", "off"); r.code != 0 || !strings.Contains(r.out, "Уведомления: выключены. Журнал пишется, как прежде") {
		t.Fatalf("%+v", r)
	}
	if r := appguard(env, "", "status"); !strings.Contains(r.out, "Уведомления: выключены") {
		t.Fatalf("статус: %s", r.out)
	}
	if r := appguard(env, "", "notifications", "on"); r.code != 0 || !strings.Contains(r.out, "Уведомления: включены.") {
		t.Fatalf("%+v", r)
	}
	if r := appguard(env, "", "notifications", "громко"); r.code != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestProtectSeveralDomainsAtOnce(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	s.DNS.Maps("claude.ai", "160.79.104.10")
	s.DNS.Maps("anthropic.com", "160.79.104.11")
	env := cli.Env{Layout: s.Layout}
	r := appguard(env, "", "protect", "claude.ai", "nosuch.example", "anthropic.com")
	if r.code != 1 || !strings.Contains(r.out, "Сервис claude.ai защищён") || !strings.Contains(r.out, "Сервис anthropic.com защищён") ||
		!strings.Contains(r.err, "Не удалось защитить nosuch.example") {
		t.Fatalf("%+v", r)
	}
	if got := s.SystemDNS.Domains(); !slices.Contains(got, "claude.ai") || !slices.Contains(got, "anthropic.com") {
		t.Fatalf("резолверы: %v", got)
	}
	if r := appguard(env, "", "unprotect", "claude.ai", "anthropic.com"); r.code != 0 || strings.Count(r.out, "защита снята") != 2 {
		t.Fatalf("%+v", r)
	}
	if r := appguard(env, "", "protect"); r.code != 2 || !strings.Contains(r.err, "можно несколько через пробел") {
		t.Fatalf("%+v", r)
	}
}

func TestProtectByNonAdminIsRefusedOnce(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: false}})
	r := appguard(cli.Env{Layout: s.Layout}, "", "protect", "claude.ai", "anthropic.com")
	if r.code != 1 || r.err == "" || strings.Count(strings.TrimSpace(r.err), "\n") != 0 || r.out != "" {
		t.Fatalf("%+v", r)
	}
}

func TestStatusShowsSystemProxy(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.SetProxy(servicetest.Proxy(12334, "Hiddify"))
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { return len(st.Paths) == 1 && st.Paths[0].State == "verified" })
	r := appguard(cli.Env{Layout: s.Layout}, "", "status")
	if !strings.Contains(r.out, "VPN: прокси 127.0.0.1:12334 (Hiddify) — выход 185.1.2.3, Германия — проверен\n") {
		t.Fatalf("%s", r.out)
	}

	s.Web.Set("95.1.2.3", "RU", "RU")
	// Порт закрывается после того, как выход признан российским, — ждём и его.
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool {
		return len(st.Paths) == 1 && st.Paths[0].State == "russian" && strings.Contains(st.Paths[0].Summary, core.PortClosed)
	})
	r = appguard(cli.Env{Layout: s.Layout}, "", "status")
	if !strings.Contains(r.out, "VPN: прокси 127.0.0.1:12334 (Hiddify) — выход в России (95.1.2.3); порт закрыт для всех программ") {
		t.Fatalf("%s", r.out)
	}
}

// syncBuffer — вывод команды, которую читают, пока она работает.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestJournalShowsEventsAsTheyHappen(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})
	var out syncBuffer
	code := make(chan int, 1)
	go func() {
		code <- cli.Run([]string{"log"}, cli.Env{Layout: s.Layout, Version: servicetest.Version, Out: &out, Err: &out, In: strings.NewReader("")})
	}()

	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(servicetest.Tunnel("utun11", "10.8.1.1"))
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(out.String(), "utun11: выход 185.1.2.3, Германия — проверен") {
		if time.Now().After(deadline) {
			t.Fatalf("журнал не показал проверку:\n%s", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "служба "+servicetest.Version+" запущена") {
		t.Fatalf("журнал не показал прошлые события:\n%s", out.String())
	}

	s.Installation.Stop() // служба останавливается
	select {
	case c := <-code:
		if c != 1 || !strings.Contains(out.String(), "журнал прерван") {
			t.Fatalf("код %d:\n%s", c, out.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("журнал не закрылся вместе со службой")
	}
}

// Служба старой версии (до таски 02) путей не присылает: команда не должна
// говорить «VPN: нет», когда просто не знает.
func TestStatusFromOlderServiceSaysNothingAboutVPN(t *testing.T) {
	L := emptyLayout(t)
	ln, err := ipc.Listen(L.Socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &ipc.Server{Logf: t.Logf, Handler: func(_ ipc.Peer, _ ipc.Request, r *ipc.Reply) func() {
		r.Send(ipc.Response{OK: true, Status: &ipc.Status{Version: "0.1.0", StartedAt: time.Now()}})
		return nil
	}}
	go srv.Serve(ln)
	defer ln.Close()

	r := appguard(cli.Env{Layout: L}, "", "status")
	if r.code != 0 || strings.Contains(r.out, "VPN") || !strings.Contains(r.out, "У этой команды версия") {
		t.Fatalf("%+v", r)
	}
}

// withApps — служба с администратором и установленными Notion и Figma.
func withApps(t *testing.T) (*servicetest.Service, cli.Env) {
	t.Helper()
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	dir := t.TempDir()
	installed := []apps.App{
		{ID: "com.figma.Desktop", Name: "Figma", Path: servicetest.App(t, dir, "Figma", "com.figma.Desktop")},
		{ID: "notion.id", Name: "Notion", Path: servicetest.App(t, dir, "Notion", "notion.id")},
	}
	return s, cli.Env{Layout: s.Layout, Installed: func() []apps.App { return installed }}
}

func TestAddAppByNameAndStatusReminds(t *testing.T) {
	s, env := withApps(t)
	r := appguard(env, "", "add", "notion")
	if r.code != 0 || !strings.Contains(r.out, "Notion добавлено и ждёт обучения") {
		t.Fatalf("%+v", r)
	}
	r = appguard(env, "", "status")
	for _, want := range []string{"Правило: любой выход не из России", "Приложения:", "Notion — ждёт обучения: ещё не защищено — включи VPN и открой его"} {
		if !strings.Contains(r.out, want) {
			t.Fatalf("в статусе нет %q:\n%s", want, r.out)
		}
	}
	if r := appguard(env, "", "add", "Нет такого"); r.code != 1 || !strings.Contains(r.err, "нет в папках «Программы»") {
		t.Fatalf("%+v", r)
	}
	if r := appguard(env, "", "add"); r.code != 2 || !strings.Contains(r.err, "Укажи приложение") {
		t.Fatalf("без имени и без терминала: %+v", r)
	}
	_ = s
}

func TestAddAppFromTheListHidesAlreadyAdded(t *testing.T) {
	_, env := withApps(t)
	env.Interactive = true
	appguard(env, "", "add", "Notion")
	// В списке остаётся только Figma: Enter выбирает её.
	r := appguard(env, "\r", "add")
	if r.code != 0 || !strings.Contains(r.out, "Figma добавлено") || strings.Contains(r.out, "   Notion") {
		t.Fatalf("%+v", r)
	}
	if r := appguard(env, "\r", "add"); !strings.Contains(r.out, "уже в списке") {
		t.Fatalf("когда добавлено всё: %+v", r)
	}
}

func TestRemoveAppWarnsAndAsks(t *testing.T) {
	_, env := withApps(t)
	appguard(env, "", "add", "Notion")
	env.Interactive = true

	r := appguard(env, "\rнет\n", "remove")
	if r.code != 1 || !strings.Contains(r.out, "с домашнего адреса") || !strings.Contains(r.out, "защита осталась") {
		t.Fatalf("отказ: %+v", r)
	}
	if r := appguard(env, "", "status"); !strings.Contains(r.out, "Notion — ждёт обучения") {
		t.Fatalf("после отказа приложение пропало: %s", r.out)
	}
	r = appguard(env, "\rда\n", "remove")
	if r.code != 0 || !strings.Contains(r.out, "С Notion защита снята") {
		t.Fatalf("согласие: %+v", r)
	}
	if r := appguard(env, "", "status"); !strings.Contains(r.out, "Приложения: пока ни одного") {
		t.Fatalf("после снятия: %s", r.out)
	}
}

func TestRemoveAppWithoutTerminalNeedsYes(t *testing.T) {
	_, env := withApps(t)
	appguard(env, "", "add", "Notion")
	if r := appguard(env, "", "remove", "Notion"); r.code != 1 || !strings.Contains(r.err, "--yes") {
		t.Fatalf("без подтверждения: %+v", r)
	}
	if r := appguard(env, "", "remove", "Notion", "--yes"); r.code != 0 {
		t.Fatalf("с --yes: %+v", r)
	}
	if r := appguard(env, "", "пауза"); r.code != 2 {
		t.Fatalf("команда «пауза» существует: %+v", r)
	}
}

func TestMenuRunsActionsAndReturns(t *testing.T) {
	s, env := withApps(t)
	env.Interactive = true
	// Вниз до «Статус», Enter, Enter — назад, страница вниз — «Выход», Enter.
	input := "\x1b[B\x1b[B\r\n\x1b[6~\r"
	r := appguard(env, input)
	if r.code != 0 || !strings.Contains(r.out, "— Статус —") || !strings.Contains(r.out, "Служба: работает") {
		t.Fatalf("%+v", r)
	}
	for _, item := range []string{"Добавить приложение", "Убрать приложение", "Журнал", "Правило", "Запомнить текущий выход", "Проверка", "Уведомления", "Удалить инструмент"} {
		if !strings.Contains(r.out, item) {
			t.Fatalf("в меню нет «%s»", item)
		}
	}
	if strings.Contains(r.out, "ауза") {
		t.Fatal("в меню есть пауза")
	}
	_ = s
}

func TestRule(t *testing.T) {
	_, env := withApps(t)
	if r := appguard(env, "", "rule"); r.code != 0 || !strings.Contains(r.out, "любой выход не из России") {
		t.Fatalf("%+v", r)
	}
}

func TestExportWritesTheCloneCatalogAndReports(t *testing.T) {
	s, env := withApps(t)
	appguard(env, "", "add", "Notion")
	appguard(env, "", "add", "Figma") // ждёт обучения
	s.Web.Set("203.0.113.89", "DE", "DE")
	s.Network.Set(servicetest.Tunnel("utun11", "10.8.1.1"))
	s.Apps.VPNServer("185.199.0.10")
	s.Apps.Run("notion.id", "208.103.161.2:443", "185.199.0.10:443")
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool {
		for _, a := range st.Apps {
			if a.ID == "notion.id" {
				return a.Learned
			}
		}
		return false
	})

	dir := t.TempDir()
	file := filepath.Join(dir, "catalog.json")
	os.WriteFile(file, []byte(`{"format": 1, "updated": "2026-09-01", "apps": [
		{"name": "Telegram", "macos": {"id": "ru.keepcoder.Telegram"}, "addrs": ["149.154.167.51"]}]}`), 0o644)

	r := appguard(env, "", "catalog", "export", file)
	if r.code != 0 || !strings.Contains(r.out, "Notion: новое приложение; адреса 208.103.161.2") ||
		!strings.Contains(r.out, "185.199.0.10 — сервер VPN") || !strings.Contains(r.out, "git diff") {
		t.Fatalf("%+v", r)
	}
	data, _ := os.ReadFile(file)
	got := string(data)
	if !strings.Contains(got, "notion.id") || !strings.Contains(got, "149.154.167.51") ||
		strings.Contains(got, "185.199.0.10") || strings.Contains(got, "com.figma.Desktop") || strings.Contains(got, "203.0.113.89") {
		t.Fatalf("каталог после выгрузки:\n%s", got)
	}

	// Повтор без нового — файл не трогается.
	r = appguard(env, "", "catalog", "export", file)
	if again, _ := os.ReadFile(file); r.code != 0 || string(again) != got || !strings.Contains(r.out, "файл не изменён") {
		t.Fatalf("повтор: %+v", r)
	}
	// Статус показывает каталог, а без каталога — что его нет.
	if r := appguard(env, "", "status"); !strings.Contains(r.out, "Каталог: не установлен") {
		t.Fatalf("%s", r.out)
	}
	if r := appguard(env, "", "catalog", "load", file); r.code != 0 {
		t.Fatalf("загрузка: %+v", r)
	}
	if r := appguard(env, "", "status"); !strings.Contains(r.out, "Каталог: от ") {
		t.Fatalf("%s", r.out)
	}
}

// withVerifiedExit — служба с администратором и проверенным выходом ip в country.
func withVerifiedExit(t *testing.T, ip, country string) (*servicetest.Service, cli.Env) {
	t.Helper()
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	s.Web.Set(ip, country, country)
	s.Network.Set(servicetest.Tunnel("utun11", "10.8.1.1"))
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { return len(st.Paths) == 1 && st.Paths[0].State != "pending" })
	return s, cli.Env{Layout: s.Layout}
}

func TestRememberAndOnlyMyExits(t *testing.T) {
	_, env := withVerifiedExit(t, "185.1.2.3", "DE")
	r := appguard(env, "", "remember", "Server", "1")
	if r.code != 0 || !strings.Contains(r.out, "Сейчас выход 185.1.2.3, Германия.") ||
		!strings.Contains(r.out, "Запомнено: Server 1 — Германия (185.1.2.3).") || !strings.Contains(r.out, "appguard rule mine") {
		t.Fatalf("%+v", r)
	}
	r = appguard(env, "", "rule", "mine")
	if r.code != 0 || !strings.Contains(r.out, "Правило: только мои выходы") || !strings.Contains(r.out, "Мои выходы: Server 1 — Германия (185.1.2.3)") {
		t.Fatalf("%+v", r)
	}
	r = appguard(env, "", "status")
	if !strings.Contains(r.out, "Правило: только мои выходы") || !strings.Contains(r.out, "Мои выходы: Server 1") {
		t.Fatalf("статус: %s", r.out)
	}
	if r := appguard(env, "", "rule", "пауза"); r.code != 2 {
		t.Fatalf("несуществующее правило: %+v", r)
	}
}

func TestRuleAndRememberInTheTerminal(t *testing.T) {
	_, env := withVerifiedExit(t, "185.1.2.3", "DE")
	env.Interactive = true
	// Вниз — «только мои выходы»; список пуст — предупреждение.
	r := appguard(env, "\x1b[B\r", "rule")
	if r.code != 0 || !strings.Contains(r.out, "Правило: только мои выходы") || !strings.Contains(r.out, "нет ни одного выхода") {
		t.Fatalf("%+v", r)
	}
	r = appguard(env, "Дом\n", "remember")
	if r.code != 0 || !strings.Contains(r.out, "Как назвать этот выход") || !strings.Contains(r.out, "Запомнено: Дом — Германия") {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(r.out, "appguard rule mine") {
		t.Fatal("правило уже «мои», а подсказка предлагает его выбрать")
	}
}

func TestRussianExitIsNotRememberedByCommand(t *testing.T) {
	_, env := withVerifiedExit(t, "95.1.2.3", "RU")
	r := appguard(env, "", "remember", "Офис")
	if r.code != 1 || !strings.Contains(r.out, "Сейчас выход 95.1.2.3, Россия.") || !strings.Contains(r.err, "российский выход не сохраняется") {
		t.Fatalf("%+v", r)
	}
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	if r := appguard(cli.Env{Layout: s.Layout}, "", "remember", "x"); r.code != 1 || !strings.Contains(r.err, "нет проверенного выхода") {
		t.Fatalf("без VPN: %+v", r)
	}
}

// Консольная программа добавляется по имени команды из PATH. Claude —
// приложение, claude — команда; совпало и то и другое — нужен путь.
func TestAddCommandByName(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	dir := t.TempDir()
	installed := []apps.App{
		{ID: "com.anthropic.claudefordesktop", Name: "Claude", Path: servicetest.App(t, dir, "Claude", "com.anthropic.claudefordesktop")},
		{ID: "tool.id", Name: "tool", Path: servicetest.App(t, dir, "tool", "tool.id")},
	}
	env := cli.Env{Layout: s.Layout, Installed: func() []apps.App { return installed }}
	bin := t.TempDir()
	for _, name := range []string{"claude", "tool"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)

	r := appguard(env, "", "add", "claude")
	if r.code != 0 || !strings.Contains(r.out, "claude добавлено и ждёт обучения") || !strings.Contains(r.out, "не открывай через неё посторонние сайты") {
		t.Fatalf("%+v", r)
	}
	if r := appguard(env, "", "add", "Claude"); r.code != 0 || !strings.Contains(r.out, "Claude добавлено") {
		t.Fatalf("приложение Claude: %+v", r)
	}
	if r := appguard(env, "", "add", "tool"); r.code != 1 || !strings.Contains(r.err, "укажи путь") || !strings.Contains(r.err, filepath.Join(bin, "tool")) {
		t.Fatalf("неоднозначное имя: %+v", r)
	}
	if r := appguard(env, "", "add", "nosuch"); r.code != 1 || !strings.Contains(r.err, "и консольной программы с таким именем тоже") {
		t.Fatalf("%+v", r)
	}
	if r := appguard(env, "", "status"); !strings.Contains(r.out, "claude — ждёт обучения: ещё не защищено — включи VPN и запусти программу") {
		t.Fatalf("статус: %s", r.out)
	}
}

// Защита одним файлом: список или выгрузка с другого компьютера.
func TestImportFile(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	s.DNS.Maps("claude.ai", "160.79.104.20")
	s.DNS.Maps("anthropic.com", "160.79.104.21")
	env := cli.Env{Layout: s.Layout}
	dir := t.TempDir()
	list := filepath.Join(dir, "list.txt")
	os.WriteFile(list, []byte("# мои сервисы\nclaude.ai\nhttps://anthropic.com/news\n160.79.104.10\n192.168.0.1\n"), 0o644)
	r := appguard(env, "", "import", list)
	if r.code != 0 || !strings.Contains(r.out, "Защищено сразу: 2 домена и 1 адрес") || !strings.Contains(r.out, "отброшено: 192.168.0.1") {
		t.Fatalf("%+v", r)
	}
	export := filepath.Join(dir, "export.json")
	os.WriteFile(export, []byte(`{"format": 1, "apps": [{"name": "Notion", "macos": {"id": "notion.id"}, "domains": ["claude.ai"], "addrs": ["208.103.161.2", "160.79.104.10"]}]}`), 0o644)
	if r := appguard(env, "", "import", export); r.code != 0 || !strings.Contains(r.out, "Защищено сразу: 0 доменов и 1 адрес") || !strings.Contains(r.out, "Ещё 2 из файла уже были под защитой") {
		t.Fatalf("выгрузка: %+v", r)
	}
	if r := appguard(env, "", "protect", "34.149.66.165"); r.code != 0 || !strings.Contains(r.out, "Адрес 34.149.66.165 защищён") {
		t.Fatalf("protect адреса: %+v", r)
	}
	if r := appguard(env, "", "status"); !strings.Contains(r.out, "Вручную: anthropic.com, claude.ai; 3 адреса") {
		t.Fatalf("статус: %s", r.out)
	}
	if r := appguard(env, "", "import", filepath.Join(dir, "нет")); r.code != 1 || !strings.Contains(r.err, "не читается") {
		t.Fatalf("%+v", r)
	}
	if r := appguard(env, "", "import"); r.code != 2 {
		t.Fatalf("%+v", r)
	}
}

// Выход по адресу без VPN, статус и «забыть» по имени без учёта регистра.
func TestRememberAndForgetExitByAddress(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	env := cli.Env{Layout: s.Layout}
	r := appguard(env, "", "remember", "Сингапур", "203.0.113.7")
	if r.code != 0 || !strings.Contains(r.out, "Запомнено: Сингапур — введён вручную, ещё не проверен (203.0.113.7)") ||
		!strings.Contains(r.out, "Нужен адрес выхода") || !strings.Contains(r.out, "appguard rule mine") {
		t.Fatalf("%+v", r)
	}
	if r := appguard(env, "", "status"); !strings.Contains(r.out, "Мои выходы: Сингапур — введён вручную, ещё не проверен (203.0.113.7)") {
		t.Fatalf("статус: %s", r.out)
	}
	if r := appguard(env, "", "remember", "Сингапур"); r.code != 1 || !strings.Contains(r.err, "appguard remember Сингапур 203.0.113.5") {
		t.Fatalf("без VPN и без адреса: %+v", r)
	}
	if r := appguard(env, "", "forget", "сингапур"); r.code != 0 || !strings.Contains(r.out, "Забыт выход: Сингапур") {
		t.Fatalf("забыть: %+v", r)
	}
	if r := appguard(env, "", "forget", "Сингапур"); r.code != 1 || !strings.Contains(r.err, "Выхода «Сингапур» в списке нет") {
		t.Fatalf("забыть ещё раз: %+v", r)
	}
	if r := appguard(env, "", "forget"); r.code != 2 || !strings.Contains(r.err, "appguard forget claude 34.149.66.165") {
		t.Fatalf("без аргументов: %+v", r)
	}
}

// Что выучило приложение — appguard status <приложение>; лишнее — appguard forget.
func TestForgetLearnedAddressFromApp(t *testing.T) {
	s, env := withApps(t)
	appguard(env, "", "add", "Notion")
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(servicetest.Tunnel("utun11", "10.8.1.1"))
	s.Apps.Run("notion.id", "208.103.161.2:443", "203.0.113.50:443")
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool {
		return len(st.Apps) == 1 && st.Apps[0].Learned && st.Apps[0].Addrs == 2
	})

	r := appguard(env, "", "status", "notion")
	if r.code != 0 || !strings.Contains(r.out, "Notion — защищено: 2 адреса") || !strings.Contains(r.out, "Адреса — 2:\n  203.0.113.50\n  208.103.161.2\n") ||
		!strings.Contains(r.out, "Домены (вместе с поддоменами): нет") || !strings.Contains(r.out, "appguard forget Notion <адрес или домен>") {
		t.Fatalf("статус приложения: %+v", r)
	}
	r = appguard(env, "", "forget", "Notion", "203.0.113.50", "198.51.100.1")
	if r.code != 0 || !strings.Contains(r.out, "У Notion забыто: 203.0.113.50. Без VPN это больше не закрыто") ||
		!strings.Contains(r.out, "198.51.100.1 у Notion не выучен") {
		t.Fatalf("забыть: %+v", r)
	}
	if r := appguard(env, "", "status", "Notion"); !strings.Contains(r.out, "Адреса — 1:\n  208.103.161.2\n") || !strings.Contains(r.out, "Забыто: 203.0.113.50") {
		t.Fatalf("после забывания: %s", r.out)
	}
	if r := appguard(env, "", "forget", "Figma", "1.2.3.4"); r.code != 1 || !strings.Contains(r.err, "нет ни выхода с таким именем, ни приложения") {
		t.Fatalf("не защищённое приложение: %+v", r)
	}
	if r := appguard(env, "", "status", "Figma"); r.code != 1 || !strings.Contains(r.err, "«Figma» нет в списке") {
		t.Fatalf("статус не защищённого: %+v", r)
	}
}
