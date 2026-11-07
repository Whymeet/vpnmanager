package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenCreatesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Get().Schema; got != Schema {
		t.Fatalf("схема %d, ждали %d", got, Schema)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("права %v, ждали 0600: настройки читает только служба", fi.Mode().Perm())
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("созданный файл не открылся снова: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("рядом с настройками остались временные файлы: %v", entries)
	}
}

func TestOpenRefusesBrokenOrNewerFile(t *testing.T) {
	for name, tc := range map[string]struct{ data, want string }{
		"не JSON":         {`{`, "повреждены"},
		"без версии":      {`{}`, "повреждены"},
		"от новой версии": {`{"schema": 99}`, "обнови инструмент"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			os.WriteFile(path, []byte(tc.data), 0o600)
			_, err := Open(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ошибка %v, ждали со словами %q", err, tc.want)
			}
			if data, _ := os.ReadFile(path); string(data) != tc.data {
				t.Fatalf("файл переписан: %q", data)
			}
		})
	}
}

func TestAppsRoundTripAndAreCopied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	added := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	if err := s.Update(func(st *Settings) {
		st.Apps = append(st.Apps, App{ID: "notion.id", Name: "Notion", Path: "/Applications/Notion.app", Added: added,
			WorkSecs: 95, Addrs: []string{"104.18.0.1"}})
	}); err != nil {
		t.Fatal(err)
	}

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got := again.Get().Apps
	if len(got) != 1 || got[0].ID != "notion.id" || got[0].WorkSecs != 95 || got[0].Learned || !got[0].Added.Equal(added) || got[0].Addrs[0] != "104.18.0.1" {
		t.Fatalf("после перезапуска: %+v", got)
	}

	// Get отдаёт копию: правка результата не должна менять хранилище.
	got[0].Addrs[0] = "6.6.6.6"
	got[0].Name = "Чужое"
	if cur := again.Get().Apps[0]; cur.Addrs[0] != "104.18.0.1" || cur.Name != "Notion" {
		t.Fatalf("хранилище изменилось снаружи: %+v", cur)
	}
}

// Файл, записанный версией до приложений (0.3–0.4), открывается как есть.
func TestSettingsWithoutAppsStillOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"schema": 1, "protected": [{"domain": "notion.so", "addrs": ["104.18.0.1"]}]}`), 0o600)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if st := s.Get(); len(st.Protected) != 1 || len(st.Apps) != 0 {
		t.Fatalf("%+v", st)
	}
}
