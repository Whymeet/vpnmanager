package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnlock/internal/cli"
	"vpnlock/internal/ipc"
	"vpnlock/internal/paths"
	"vpnlock/internal/service/servicetest"
)

// Ежедневное обновление каталога (таска 13) с настоящим git: репозиторий
// курса — голый репозиторий во временной папке, клон ученика — его клон.

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func catalogJSON(day string) string {
	return `{"format": 1, "updated": "` + day + `", "apps": [
		{"name": "Notion", "macos": {"id": "notion.id"}, "domains": ["notion.so"]}]}`
}

// course — репозиторий курса и клон ученика; author — клон, из которого
// автор публикует. Возвращает клон ученика и функцию публикации.
func course(t *testing.T) (clone string, publish func(path, data string)) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("нет git")
	}
	root := t.TempDir()
	origin := filepath.Join(root, "origin.git")
	author := filepath.Join(root, "author")
	clone = filepath.Join(root, "student")
	git(t, root, "init", "--quiet", "--bare", "-b", "main", origin)
	git(t, root, "clone", "--quiet", origin, author)
	publish = func(path, data string) {
		os.MkdirAll(filepath.Dir(filepath.Join(author, path)), 0o755)
		os.WriteFile(filepath.Join(author, path), []byte(data), 0o644)
		git(t, author, "add", "-A")
		git(t, author, "commit", "--quiet", "-m", "publish "+path)
		git(t, author, "push", "--quiet", "origin", "HEAD:main")
	}
	publish("catalog/catalog.json", catalogJSON("2026-10-01"))
	publish("internal/version/VERSION", servicetest.Version+"\n")
	git(t, root, "clone", "--quiet", origin, clone)
	return clone, publish
}

// syncEnv — служба, поставленная из клона clone; задача каталога работает от
// имени его владельца.
func syncEnv(t *testing.T, clone string) (*servicetest.Service, cli.Env) {
	root := t.TempDir()
	L := paths.Under(root)
	os.MkdirAll(L.AppDir, 0o755)
	os.WriteFile(L.CloneFile, []byte(clone), 0o644)
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Owner: true}})
	return s, cli.Env{Layout: s.Layout}
}

func TestDailySyncBringsTheNewCatalog(t *testing.T) {
	clone, publish := course(t)
	s, env := syncEnv(t, clone)
	if r := vpnlock(env, "", "catalog", "sync", clone); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if st := s.Status(t); st.Catalog != "2026-10-01" {
		t.Fatalf("каталог: %+v", st)
	}

	// Автор опубликовал новый каталог — назавтра он у ученика.
	publish("catalog/catalog.json", catalogJSON("2026-10-08"))
	if r := vpnlock(env, "", "catalog", "sync", clone); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if st := s.Status(t); st.Catalog != "2026-10-08" || st.SyncProblem != "" {
		t.Fatalf("каталог: %+v", st)
	}
	if r := vpnlock(env, "", "status"); !strings.Contains(r.out, "Каталог: от 08.10.2026") {
		t.Fatalf("статус: %s", r.out)
	}
}

func TestDivergedCloneChangesNothing(t *testing.T) {
	clone, publish := course(t)
	s, env := syncEnv(t, clone)
	vpnlock(env, "", "catalog", "sync", clone)

	// Ученик закоммитил своё, автор — своё: история разошлась.
	os.WriteFile(filepath.Join(clone, "notes.txt"), []byte("моё"), 0o644)
	git(t, clone, "add", "-A")
	git(t, clone, "commit", "--quiet", "-m", "моё")
	head := git(t, clone, "rev-parse", "HEAD")
	publish("catalog/catalog.json", catalogJSON("2026-10-08"))

	r := vpnlock(env, "", "catalog", "sync", clone)
	if r.code != 1 || !strings.Contains(r.out, "история клона разошлась") {
		t.Fatalf("%+v", r)
	}
	if got := git(t, clone, "rev-parse", "HEAD"); got != head {
		t.Fatal("обновление тронуло историю клона")
	}
	if st := s.Status(t); st.Catalog != "2026-10-01" || !strings.Contains(st.SyncProblem, "история клона разошлась") {
		t.Fatalf("статус: %+v", st)
	}
	hasJournal(t, s, "каталог не обновился: история клона разошлась с репозиторием — обновление ничего не меняет")
	hasJournal(t, s, "защита работает на каталоге от 01.10.2026")
}

func TestLocalChangesAreLeftAlone(t *testing.T) {
	clone, publish := course(t)
	_, env := syncEnv(t, clone)
	mine := `{"format": 1, "updated": "2026-10-02", "apps": []}`
	os.WriteFile(filepath.Join(clone, "catalog/catalog.json"), []byte(mine), 0o644)
	publish("catalog/catalog.json", catalogJSON("2026-10-08"))

	r := vpnlock(env, "", "catalog", "sync", clone)
	if r.code != 1 || !strings.Contains(r.out, "в клоне правки в файлах, которые меняет обновление") {
		t.Fatalf("%+v", r)
	}
	if data, _ := os.ReadFile(filepath.Join(clone, "catalog/catalog.json")); string(data) != mine {
		t.Fatal("обновление тронуло локальную правку")
	}
}

func TestUnreachableOrMissingClone(t *testing.T) {
	clone, _ := course(t)
	s, env := syncEnv(t, clone)
	vpnlock(env, "", "catalog", "sync", clone)

	git(t, clone, "remote", "set-url", "origin", filepath.Join(t.TempDir(), "gone.git"))
	if r := vpnlock(env, "", "catalog", "sync", clone); r.code != 1 || !strings.Contains(r.out, "не удалось связаться с репозиторием") {
		t.Fatalf("%+v", r)
	}
	if st := s.Status(t); st.Catalog != "2026-10-01" {
		t.Fatalf("каталог сменился: %+v", st)
	}

	moved := clone + "-moved"
	os.Rename(clone, moved)
	if r := vpnlock(env, "", "catalog", "sync", clone); r.code != 1 || !strings.Contains(r.out, "не найден — перемещён или удалён") {
		t.Fatalf("%+v", r)
	}
	hasJournal(t, s, "каталог не обновился: клон "+clone+" не найден — перемещён или удалён")
}

func TestNewVersionInTheCloneIsReminded(t *testing.T) {
	clone, publish := course(t)
	s, env := syncEnv(t, clone)
	publish("internal/version/VERSION", "10.0.0\n")
	vpnlock(env, "", "catalog", "sync", clone)
	if st := s.Status(t); st.NewVersion != "10.0.0" {
		t.Fatalf("статус: %+v", st)
	}
	hasJournal(t, s, "в клоне новая версия vpnlock 10.0.0 (работает "+servicetest.Version+")")
	if r := vpnlock(env, "", "status"); !strings.Contains(r.out, "Новая версия: в клоне 10.0.0") {
		t.Fatalf("статус: %s", r.out)
	}
}

func hasJournal(t *testing.T, s *servicetest.Service, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var lines []string
		ipc.Stream(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdJournal, Tail: 1000}, func(r ipc.Response) error {
			if r.Event != nil {
				lines = append(lines, r.Event.Text)
			}
			return nil
		})
		for _, l := range lines {
			if strings.Contains(l, want) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("в журнале нет %q:\n%s", want, strings.Join(lines, "\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
