package catalog

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParseDropsWhatCannotBeThere(t *testing.T) {
	c, warnings, err := Parse([]byte(`{"format": 1, "updated": "2026-10-15", "apps": [
		{"name": "Notion", "macos": {"id": "notion.id"}, "domains": ["notion.so", "../etc", "notion.com"],
		 "addrs": ["208.103.161.2", "127.0.0.1", "1.1.1.1", "nonsense", "192.168.1.1"]},
		{"name": "", "macos": {"id": "x"}},
		{"name": "Без идентификатора", "macos": {"id": ""}}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Apps) != 1 {
		t.Fatalf("приложения %+v", c.Apps)
	}
	n := c.Apps[0]
	if !slices.Equal(n.Domains, []string{"notion.so", "notion.com"}) || !slices.Equal(n.Addrs, []string{"208.103.161.2"}) {
		t.Fatalf("запись %+v", n)
	}
	if len(warnings) != 7 {
		t.Fatalf("предупреждений %d: %v", len(warnings), warnings)
	}
	if a, ok := c.ForMac("notion.id"); !ok || a.Name != "Notion" {
		t.Fatal("по идентификатору не найдено")
	}
	if _, ok := c.ForMac("other"); ok {
		t.Fatal("найдено чужое")
	}
}

func TestParseRefusesNewerFormat(t *testing.T) {
	if _, _, err := Parse([]byte(`{"format": 2, "apps": []}`)); !errors.Is(err, ErrNewer) {
		t.Fatalf("каталог новее формата: %v", err)
	}
	for _, bad := range []string{`{"apps": []}`, `{`, `[]`} {
		if _, _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("%s принят", bad)
		}
	}
}

func TestMergeAddsOnlyWhatWasLearned(t *testing.T) {
	cur := Catalog{Format: 1, Updated: "2026-09-01", Apps: []App{
		{Name: "Figma", MacOS: &MacOS{ID: "com.figma.Desktop"}, Domains: []string{"figma.com"}, Addrs: []string{"1.2.3.4"}},
		{Name: "Notion", MacOS: &MacOS{ID: "notion.id"}, Windows: &Windows{Exe: []string{"Notion.exe"}}, Domains: []string{"notion.so"}},
	}}
	learned := []Learned{{
		Name: "Notion", ID: "notion.id",
		Domains: []string{"api.notion.so", "www.notion.com", "student.github.io", "notion.so"},
		Addrs:   []string{"208.103.161.2"},
	}}
	out, rep := Merge(cur, learned, "2026-10-15")

	figma := out.Apps[0]
	if figma.Name != "Figma" || !slices.Equal(figma.Domains, []string{"figma.com"}) || !slices.Equal(figma.Addrs, []string{"1.2.3.4"}) {
		t.Fatalf("выгрузка тронула приложение, на котором не учились: %+v", figma)
	}
	notion := out.Apps[1]
	if !slices.Equal(notion.Domains, []string{"notion.so", "notion.com"}) || !slices.Equal(notion.Addrs, []string{"208.103.161.2"}) {
		t.Fatalf("Notion: %+v", notion)
	}
	if notion.Windows == nil || notion.Windows.Exe[0] != "Notion.exe" {
		t.Fatal("выгрузка с мака стёрла идентификатор для Windows")
	}
	if out.Updated != "2026-10-15" || out.Format != Format {
		t.Fatalf("каталог: %+v", out)
	}
	if len(rep.Changes) != 1 || rep.Changes[0].New || !slices.Equal(rep.Changes[0].Domains, []string{"notion.com"}) {
		t.Fatalf("отчёт об изменениях: %+v", rep.Changes)
	}
	if len(rep.Drops) != 1 || rep.Drops[0].Value != "student.github.io" || !strings.Contains(rep.Drops[0].Why, "похоже на личное") {
		t.Fatalf("отчёт об отброшенном: %+v", rep.Drops)
	}
}

func TestMergeNewAppAndNothingNew(t *testing.T) {
	out, rep := Merge(Catalog{Format: 1, Updated: "2026-09-01"},
		[]Learned{{Name: "Telegram", ID: "ru.keepcoder.Telegram", Addrs: []string{"149.154.167.51"}}}, "2026-10-15")
	if len(out.Apps) != 1 || out.Apps[0].MacOS.ID != "ru.keepcoder.Telegram" || !rep.Changes[0].New {
		t.Fatalf("%+v %+v", out, rep)
	}
	again, rep2 := Merge(out, []Learned{{Name: "Telegram", ID: "ru.keepcoder.Telegram", Addrs: []string{"149.154.167.51"}}}, "2026-11-01")
	if len(rep2.Changes) != 0 || again.Updated != "2026-10-15" {
		t.Fatalf("повторная выгрузка без нового сменила каталог: %+v %+v", again, rep2)
	}
}

func TestFoldKeepsSharedHostingTenantsOut(t *testing.T) {
	for in, want := range map[string]string{
		"api.notion.so":       "notion.so",
		"Notion.so":           "notion.so",
		"cdn.figma.com":       "figma.com",
		"a.b.c.co.uk":         "c.co.uk",
		"me.github.io":        "",
		"d1x2.cloudfront.net": "",
		"localhost":           "",
	} {
		got, _, why := fold(in, func(string) bool { return true })
		if got != want || (want == "" && why == "") {
			t.Errorf("%s: %q (%s), ждали %q", in, got, why, want)
		}
	}
}

// Сторонние домены (аналитика, отчёты об ошибках) — точным именем: свёрнутый
// sentry.io закрыл бы вне VPN весь сервис у всех учеников. Свои домены сервиса
// узнаются по записи в каталоге, идентификатору пакета и имени приложения.
func TestMergeKeepsThirdPartyDomainsExact(t *testing.T) {
	cur := Catalog{Format: 1, Apps: []App{{Name: "Notion", MacOS: &MacOS{ID: "notion.id"}, Domains: []string{"notion.so"}}}}
	learned := []Learned{
		{Name: "Notion", ID: "notion.id", Domains: []string{"api.notion.so", "msgstore.www.notion.com", "o1.ingest.sentry.io", "api.segment.io"}},
		{Name: "ChatGPT", ID: "com.openai.chat", Domains: []string{"ab.chatgpt.com", "api.openai.com", "browser-intake-datadoghq.com"}},
	}
	out, rep := Merge(cur, learned, "2026-10-15")
	want := map[string][]string{
		"Notion":  {"notion.so", "notion.com", "o1.ingest.sentry.io", "api.segment.io"},
		"ChatGPT": {"chatgpt.com", "openai.com", "browser-intake-datadoghq.com"},
	}
	for _, a := range out.Apps {
		if !slices.Equal(a.Domains, want[a.Name]) {
			t.Errorf("%s: %v, ждали %v", a.Name, a.Domains, want[a.Name])
		}
	}
	exact := map[string][]string{}
	for _, c := range rep.Changes {
		exact[c.App] = c.Exact
	}
	if !slices.Equal(exact["Notion"], []string{"o1.ingest.sentry.io", "api.segment.io"}) || !slices.Equal(exact["ChatGPT"], []string{"browser-intake-datadoghq.com"}) {
		t.Fatalf("отчёт о сторонних: %+v", rep.Changes)
	}
}

func TestMarshalIsReadable(t *testing.T) {
	data, err := Marshal(Catalog{Format: 1, Apps: []App{}})
	if err != nil || !strings.HasSuffix(string(data), "}\n") || !strings.Contains(string(data), "\n  \"apps\": []") {
		t.Fatalf("%q %v", data, err)
	}
}

func TestForWindowsByExeOrStore(t *testing.T) {
	c, _, err := Parse([]byte(`{"format": 1, "apps": [
		{"name": "Notion", "windows": {"exe": ["Notion.exe"]}},
		{"name": "Spotify", "windows": {"store": "SpotifyAB.SpotifyMusic_zpdnekdrzrea0"}},
		{"name": "Только мак", "macos": {"id": "only.mac"}}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := c.ForWindows("NOTION.EXE", ""); !ok || a.Name != "Notion" {
		t.Fatal("по имени exe не найдено")
	}
	if a, ok := c.ForWindows("", "spotifyab.spotifymusic_zpdnekdrzrea0"); !ok || a.Name != "Spotify" {
		t.Fatal("по пакету Store не найдено")
	}
	for _, q := range [][2]string{{"Update.exe", ""}, {"", "Other_zpdnekdrzrea0"}, {"", ""}} {
		if a, ok := c.ForWindows(q[0], q[1]); ok {
			t.Fatalf("%q найдено как %s", q, a.Name)
		}
	}
}

// Консольная программа: в каталоге — имя команды. Свои домены (с именем
// программы) сворачиваются, Anthropic и телеметрия — точным именем.
func TestMergeAndFindCommand(t *testing.T) {
	cur := Catalog{Format: 1, Apps: []App{{Name: "Claude", MacOS: &MacOS{ID: "com.anthropic.claudefordesktop"}}}}
	out, rep := Merge(cur, []Learned{{
		Name: "claude", Command: "claude",
		Domains: []string{"api.claude.ai", "api.anthropic.com", "http-intake.logs.us5.datadoghq.com"},
	}}, "2026-10-16")
	c, ok := out.ForMacCommand("claude")
	if !ok || c.MacOS.ID != "" || len(out.Apps) != 2 || !rep.Changes[0].New ||
		!slices.Equal(c.Domains, []string{"claude.ai", "api.anthropic.com", "http-intake.logs.us5.datadoghq.com"}) {
		t.Fatalf("%+v %+v", out, rep)
	}
	// Пакет и команда не путаются: приложение Claude — по идентификатору пакета.
	if a, ok := out.ForMac("com.anthropic.claudefordesktop"); !ok || a.Name != "Claude" {
		t.Fatalf("%+v", a)
	}
	if _, ok := out.ForMac(""); ok {
		t.Fatal("пустой идентификатор пакета нашёл запись команды")
	}
	if _, ok := out.ForMacCommand(""); ok {
		t.Fatal("пустое имя команды нашло пакет")
	}
	// Запись только с командой переживает разбор.
	data, _ := Marshal(out)
	back, warnings, err := Parse(data)
	if _, ok := back.ForMacCommand("claude"); err != nil || len(warnings) != 0 || !ok {
		t.Fatalf("%v %v %+v", err, warnings, back)
	}
}
