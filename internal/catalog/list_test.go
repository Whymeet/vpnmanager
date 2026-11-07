package catalog

import (
	"slices"
	"strings"
	"testing"
)

func TestParseListText(t *testing.T) {
	list := `# Claude и Claude Code
anthropic.com, claude.ai
https://claude.com/new   # ссылка — берётся имя
*.datadoghq.com
160.79.104.10 [2607:6bc0::10]
CLAUDE.AI
10.0.0.0/8
не домен
`
	domains, addrs, warnings, err := ParseList([]byte(list))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(domains, []string{"anthropic.com", "claude.ai", "claude.com", "datadoghq.com"}) {
		t.Errorf("домены %v", domains)
	}
	if !slices.Equal(addrs, []string{"160.79.104.10", "2607:6bc0::10"}) {
		t.Errorf("адреса %v", addrs)
	}
	if len(warnings) != 3 || !strings.Contains(strings.Join(warnings, "\n"), "диапазоны не поддерживаются") {
		t.Errorf("предупреждения %q", warnings)
	}
}

// Выгрузка vpnlock catalog export — домены и адреса всех приложений.
func TestParseListExport(t *testing.T) {
	export := `{"format": 1, "apps": [
		{"name": "Claude", "macos": {"id": "com.anthropic.claudefordesktop"}, "domains": ["claude.ai"], "addrs": ["160.79.104.10"]},
		{"name": "claude", "macos": {"command": "claude"}, "domains": ["api.anthropic.com", "claude.ai"], "addrs": ["34.149.66.165", "127.0.0.1"]}]}`
	domains, addrs, warnings, err := ParseList([]byte(export))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(domains, []string{"api.anthropic.com", "claude.ai"}) || !slices.Equal(addrs, []string{"160.79.104.10", "34.149.66.165"}) || len(warnings) != 1 {
		t.Fatalf("%v %v %q", domains, addrs, warnings)
	}
	if _, _, _, err := ParseList([]byte(`{"format": 99, "apps": []}`)); err == nil {
		t.Fatal("каталог новее поддерживаемого разобран")
	}
}
