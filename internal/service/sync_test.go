package service_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnlock/internal/config"
	"vpnlock/internal/ipc"
	"vpnlock/internal/paths"
	"vpnlock/internal/service/servicetest"
)

// Сценарии таски 13 на шве: итог ежедневного обновления приходит от задачи,
// а служба помнит, когда каталог сверялся с репозиторием.

const syncCatalog = `{"format": 1, "updated": "2026-10-01", "apps": [
	{"name": "Notion", "macos": {"id": "notion.id"}, "domains": ["notion.so"]}]}`

func TestStaleCatalogIsReminded(t *testing.T) {
	root := t.TempDir()
	L := paths.Under(root)
	os.MkdirAll(L.StateDir, 0o700)
	os.WriteFile(filepath.Join(L.StateDir, "catalog.json"), []byte(syncCatalog), 0o600)
	cfg, err := config.Open(L.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Update(func(s *config.Settings) {
		s.CatalogChecked = time.Now().Add(-10 * 24 * time.Hour)
		s.SyncProblem = "доступ к репозиторию закрыт (Repository not found)"
	})

	s := servicetest.Start(t, root, servicetest.Fakes{})
	hasLine(t, s, "каталог не обновлялся 10 дней: доступ к репозиторию закрыт (Repository not found) — защита работает на каталоге от 01.10.2026")
	if st := s.Status(t); st.CatalogStale != 10 || st.Catalog != "2026-10-01" {
		t.Fatalf("статус: %+v", st)
	}
}

// cloneWith — клон с каталогом data и версией инструмента, из которого
// «поставлен» vpnlock в каталоге root.
func cloneWith(t *testing.T, root, data string) string {
	t.Helper()
	clone := t.TempDir()
	os.MkdirAll(filepath.Join(clone, "catalog"), 0o755)
	os.MkdirAll(filepath.Join(clone, "internal", "version"), 0o755)
	os.WriteFile(filepath.Join(clone, "catalog", "catalog.json"), []byte(data), 0o644)
	os.WriteFile(filepath.Join(clone, "internal", "version", "VERSION"), []byte(servicetest.Version+"\n"), 0o644)
	L := paths.Under(root)
	os.MkdirAll(L.AppDir, 0o755)
	os.WriteFile(L.CloneFile, []byte(clone), 0o644)
	return clone
}

func sendSync(t *testing.T, s *servicetest.Service, req ipc.Request) ipc.Response {
	t.Helper()
	req.Cmd = ipc.CmdSync
	resp, err := ipc.Call(s.Layout.Socket, req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestFailedSyncKeepsTheLastCatalog(t *testing.T) {
	root := t.TempDir()
	cloneWith(t, root, syncCatalog)
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Owner: true}})
	ok := func(req ipc.Request) {
		t.Helper()
		if resp := sendSync(t, s, req); !resp.OK {
			t.Fatalf("%+v", resp)
		}
	}
	ok(ipc.Request{})
	ok(ipc.Request{Problem: "доступ к репозиторию закрыт (Repository not found)"})
	hasLine(t, s, "каталог не обновился: доступ к репозиторию закрыт (Repository not found) — защита работает на каталоге от 01.10.2026")
	if st := s.Status(t); st.Catalog != "2026-10-01" || st.CatalogStale != 0 || st.SyncProblem == "" {
		t.Fatalf("статус: %+v", st)
	}
	// Удачное обновление снимает напоминание.
	ok(ipc.Request{})
	if st := s.Status(t); st.SyncProblem != "" {
		t.Fatalf("статус: %+v", st)
	}
}

// Итог обновления присылает администратор или владелец клона (на Windows
// задача каталога работает без повышения). Остальным — отказ.
func TestSyncNeedsAdminOrCloneOwner(t *testing.T) {
	for _, who := range []*servicetest.Accounts{{Admin: true}, {Owner: true}} {
		root := t.TempDir()
		cloneWith(t, root, syncCatalog)
		s := servicetest.Start(t, root, servicetest.Fakes{Accounts: who})
		if resp := sendSync(t, s, ipc.Request{}); !resp.OK || s.Status(t).Catalog != "2026-10-01" {
			t.Fatalf("admin=%v owner=%v: %+v", who.Admin, who.Owner, resp)
		}
	}
	root := t.TempDir()
	cloneWith(t, root, syncCatalog)
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{}})
	if resp := sendSync(t, s, ipc.Request{}); resp.OK || resp.Code != ipc.CodeForbidden {
		t.Fatalf("%+v", resp)
	}
}

// Каталог служба берёт из клона сама: присланный вместе с итогом не
// применяется.
func TestSyncTakesTheCatalogOnlyFromTheClone(t *testing.T) {
	root := t.TempDir()
	cloneWith(t, root, syncCatalog)
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Owner: true}})
	other := strings.Replace(syncCatalog, "2026-10-01", "2026-12-31", 1)
	if resp := sendSync(t, s, ipc.Request{Catalog: []byte(other)}); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	if st := s.Status(t); st.Catalog != "2026-10-01" {
		t.Fatalf("применён присланный каталог: %+v", st)
	}
}

// В клон пишут и обычные программы. Ссылка из клона наружу не читается (служба
// работает от root), и тогда обновление не удалось, а защита — на прежнем
// каталоге.
func TestSyncDoesNotFollowLinksOutOfTheClone(t *testing.T) {
	root := t.TempDir()
	clone := cloneWith(t, root, syncCatalog)
	outside := filepath.Join(t.TempDir(), "catalog.json")
	os.WriteFile(outside, []byte(syncCatalog), 0o600)
	link := filepath.Join(clone, "catalog", "catalog.json")
	os.Remove(link)
	if err := os.Symlink(outside, link); err != nil {
		t.Skip(err)
	}
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Owner: true}})
	sendSync(t, s, ipc.Request{})
	hasLine(t, s, "каталог не обновился: в клоне "+clone+" не прочитать catalog/catalog.json")
	if st := s.Status(t); st.Catalog != "" || st.SyncProblem == "" {
		t.Fatalf("каталог прочитан по ссылке из клона: %+v", st)
	}
}

// Причина неудачи — текст от клиента: в журнал и статус он идёт одной строкой
// без управляющих символов.
func TestSyncProblemIsOneCleanLine(t *testing.T) {
	root := t.TempDir()
	cloneWith(t, root, syncCatalog)
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Owner: true}})
	sendSync(t, s, ipc.Request{Problem: "\x1b[2Jнет доступа\x07\nвторая строка"})
	if st := s.Status(t); st.SyncProblem != "[2Jнет доступа" {
		t.Fatalf("причина: %q", st.SyncProblem)
	}
}
