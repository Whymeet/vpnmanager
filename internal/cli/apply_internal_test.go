package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Конфиг разбирается целиком до изменений: команды, аргументы, номера строк.
func TestParseConfig(t *testing.T) {
	data := "\uFEFF# комментарий\r\n" +
		"app claude\r\n" +
		"APP C:\\Program Files\\Notion\\Notion.exe   # путь с пробелом\n" +
		"app \"~/Applications/My App.app\"\n" +
		"\n" +
		"protect claude.ai 160.79.104.10\n" +
		"import list.txt\n" +
		"exit Server 1 203.0.113.5\n" +
		"rule Mine\n" +
		"notifications off\n"
	lines, err := parseConfig([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	want := []confLine{
		{2, "app", []string{"claude"}},
		{3, "app", []string{`C:\Program Files\Notion\Notion.exe`}},
		{4, "app", []string{"~/Applications/My App.app"}},
		{6, "protect", []string{"claude.ai", "160.79.104.10"}},
		{7, "import", []string{"list.txt"}},
		{8, "exit", []string{"Server", "1", "203.0.113.5"}},
		{9, "rule", []string{"Mine"}},
		{10, "notifications", []string{"off"}},
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("%+v", lines)
	}
}

func TestParseConfigRefusesWholeFile(t *testing.T) {
	for _, tc := range []struct{ data, want string }{
		{"app claude\nrule maybe\n", "строка 2: нужно rule mine или rule any"},
		{"exit Германия\n", "строка 1: нужно имя и адрес выхода"},
		{"exit Германия сервер\n", "«сервер» — не адрес"},
		{"app\n", "нужно имя или путь"},
		{"protect\n", "нужен домен или адрес"},
		{"import\n", "нужен файл"},
		{"notifications maybe\n", "нужно notifications on или notifications off"},
		{"add claude\n", "нет команды «add»"},
		{"# только комментарии\n\n", "нет ни одной команды"},
	} {
		if _, err := parseConfig([]byte(tc.data)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, ждали %q", tc.data, err, tc.want)
		}
	}
}

// Конфиг своей системы: сборка знает, под какую систему она собрана.
func TestConfigName(t *testing.T) {
	for goos, want := range map[string]string{"darwin": "macos.conf", "linux": "linux.conf", "windows": "windows.conf"} {
		if got := configName(goos); got != want {
			t.Errorf("%s → %s, ждали %s", goos, got, want)
		}
	}
}

// В клоне лежит конфиг для каждой системы, и каждый разбирается.
func TestRepoConfigsParse(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "configs", configName(goos)))
		if err != nil {
			t.Fatal(err)
		}
		lines, err := parseConfig(data)
		if err != nil {
			t.Fatalf("%s: %v", configName(goos), err)
		}
		// Свои выходы и правило у каждого свои: общий конфиг их не задаёт.
		for _, l := range lines {
			if l.key == "exit" || l.key == "rule" {
				t.Errorf("%s, строка %d: %s в общем конфиге", configName(goos), l.n, l.key)
			}
		}
	}
}

// Конфиг проекта «Claude только через свои VPN»: разбирается, задаёт правило
// mine (без него Claude открывался бы через любой VPN) и не держит выходов —
// их вводит пользователь в окне «Мои VPN».
func TestClaudeVPNConfigParses(t *testing.T) {
	for _, name := range []string{"claude-vpn.conf", "claude-vpn-macos.conf"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "configs", name))
		if err != nil {
			t.Fatal(err)
		}
		lines, err := parseConfig(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var mine bool
		for _, l := range lines {
			mine = mine || (l.key == "rule" && len(l.args) == 1 && l.args[0] == "mine")
			if l.key == "exit" {
				t.Errorf("%s, строка %d: выход в общем конфиге — выходы вводит пользователь", name, l.n)
			}
		}
		if !mine {
			t.Fatalf("%s: нет rule mine", name)
		}
	}
}

func TestExpandPercent(t *testing.T) {
	env := map[string]string{"USERPROFILE": `C:\Users\Иван`}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	for in, want := range map[string]string{
		`%USERPROFILE%\.local\bin\claude.exe`: `C:\Users\Иван\.local\bin\claude.exe`,
		`%NOSUCH%\app.exe`:                    `%NOSUCH%\app.exe`,
		`C:\100%\app.exe`:                     `C:\100%\app.exe`,
	} {
		if got := expandPercent(in, lookup); got != want {
			t.Errorf("%s → %s, ждали %s", in, got, want)
		}
	}
}
