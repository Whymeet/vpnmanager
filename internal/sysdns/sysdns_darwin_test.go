package sysdns

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func resolvers(t *testing.T) (Resolvers, *int) {
	flushes := 0
	return Resolvers{
		Dir:   filepath.Join(t.TempDir(), "resolver"),
		Addr:  netip.MustParseAddrPort("127.0.0.1:53535"),
		Flush: func() error { flushes++; return nil },
	}, &flushes
}

func TestSetWritesAndRemovesOnlyOurs(t *testing.T) {
	r, flushes := resolvers(t)
	os.MkdirAll(r.Dir, 0o755)
	os.WriteFile(filepath.Join(r.Dir, "corp.example"), []byte("nameserver 10.0.0.1\n"), 0o644)

	if skipped, err := r.Set([]string{"notion.so", "figma.com"}); err != nil || len(skipped) != 0 {
		t.Fatalf("%v %v", skipped, err)
	}
	data, _ := os.ReadFile(filepath.Join(r.Dir, "notion.so"))
	for _, want := range []string{"# appguard", "nameserver 127.0.0.1", "port 53535"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("в файле нет %q:\n%s", want, data)
		}
	}
	if *flushes != 1 {
		t.Fatalf("кэш DNS сброшен %d раз", *flushes)
	}
	if _, err := r.Set([]string{"notion.so", "figma.com"}); err != nil || *flushes != 1 {
		t.Fatalf("повтор без изменений сбросил кэш: %d %v", *flushes, err)
	}

	r.Set([]string{"notion.so"})
	if _, err := os.Stat(filepath.Join(r.Dir, "figma.com")); !os.IsNotExist(err) {
		t.Fatal("снятый домен остался направленным на службу")
	}
	if err := r.Clear(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(r.Dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"corp.example"}) {
		t.Fatalf("после удаления в каталоге %v, а должен остаться только чужой файл", names)
	}
}

func TestForeignFileIsNeverOverwritten(t *testing.T) {
	r, _ := resolvers(t)
	os.MkdirAll(r.Dir, 0o755)
	foreign := filepath.Join(r.Dir, "notion.so")
	os.WriteFile(foreign, []byte("nameserver 10.0.0.1\n"), 0o644)

	skipped, err := r.Set([]string{"notion.so"})
	if err != nil || !slices.Equal(skipped, []string{"notion.so"}) {
		t.Fatalf("%v %v", skipped, err)
	}
	if data, _ := os.ReadFile(foreign); string(data) != "nameserver 10.0.0.1\n" {
		t.Fatalf("чужой файл переписан: %s", data)
	}
	r.Clear()
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("удаление сняло чужой файл")
	}
}
