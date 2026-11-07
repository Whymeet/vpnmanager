package cli

import (
	"testing"

	"vpnlock/internal/ipc"
)

// Claude — приложение, claude — Claude Code: точное имя решает; без учёта
// регистра имя подходит, только когда такое приложение одно.
func TestFindAppPrefersExactName(t *testing.T) {
	list := []ipc.AppStatus{{ID: "com.anthropic.claudefordesktop", Name: "Claude"}, {ID: "cmd:/x/claude", Name: "claude"}, {ID: "notion.id", Name: "Notion"}}
	for name, want := range map[string]string{"Claude": "com.anthropic.claudefordesktop", "claude": "cmd:/x/claude", "notion": "notion.id", "notion.id": "notion.id"} {
		if a, ok := findApp(list, name); !ok || a.ID != want {
			t.Errorf("%s: %+v %v, нужно %s", name, a, ok, want)
		}
	}
	if a, ok := findApp(list, "CLAUDE"); ok {
		t.Errorf("CLAUDE подходит двоим, а выбрано %+v", a)
	}
}
