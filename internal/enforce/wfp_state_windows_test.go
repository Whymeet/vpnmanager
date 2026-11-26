package enforce

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// После сбоя системы wfp.json бывает из нулей — служба не должна застревать.
func TestWFPStateCorruptStartsEmpty(t *testing.T) {
	file := filepath.Join(t.TempDir(), "wfp.json")
	if err := os.WriteFile(file, make([]byte, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	var logged []string
	w := &WFP{StateFile: file, Logf: func(f string, a ...any) { logged = append(logged, f) }}
	state, err := w.load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if state.Apps == nil || len(state.Apps) != 0 || len(state.Addrs) != 0 {
		t.Fatalf("state = %+v, нужен пустой", state)
	}
	if _, err := os.Stat(file + ".bad"); err != nil {
		t.Fatalf("испорченный файл не отложен: %v", err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "испорчен") {
		t.Fatalf("журнал: %q", logged)
	}
	want := wfpState{Apps: map[string][]string{"a": {"k"}}, Addrs: []string{"1.2.3.4"}}
	if err := w.save(want); err != nil {
		t.Fatal(err)
	}
	got, err := w.load()
	if err != nil || len(got.Apps["a"]) != 1 || got.Addrs[0] != "1.2.3.4" {
		t.Fatalf("load после save = %+v, %v", got, err)
	}
	if _, err := os.Stat(file + ".new"); !os.IsNotExist(err) {
		t.Fatalf("временный файл остался: %v", err)
	}
}
