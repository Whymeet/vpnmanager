package install

import (
	"encoding/xml"
	"strings"
	"testing"
)

// Задача каталога запускает git в клоне, куда пишут и обычные программы: с
// наивысшими правами хук git получил бы права администратора без окна UAC.
func TestCatalogTaskRunsWithoutElevation(t *testing.T) {
	x := catalogTaskXML(`C:\Program Files\appguard\bin\appguardw.exe`, `C:\Users\student\appguard`, "S-1-5-21-1-2-3-1001")
	if !strings.Contains(x, "<RunLevel>LeastPrivilege</RunLevel>") || strings.Contains(x, "HighestAvailable") {
		t.Fatal(x)
	}
}

// Значок работает в сеансе каждого пользователя, без окна и без прав администратора,
// сколько угодно долго. Parallel: /Run при обновлении запускает второй экземпляр, его
// останавливает мьютекс, а IgnoreNew не дал бы значку подняться у другого пользователя.
func TestTrayTaskRunsInEveryUserSession(t *testing.T) {
	x := userTaskXML(`C:\Program Files\appguard\bin\appguardw.exe`, "tray", "appguard: значок службы рядом с часами")
	for _, want := range []string{
		"<LogonTrigger>", "<GroupId>S-1-5-32-545</GroupId>", "<RunLevel>LeastPrivilege</RunLevel>",
		"<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>", "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
		"<Arguments>tray</Arguments>", "<Description>appguard: значок службы рядом с часами</Description>",
		`<Command>C:\Program Files\appguard\bin\appguardw.exe</Command>`,
	} {
		if !strings.Contains(x, want) {
			t.Fatalf("нет %q:\n%s", want, x)
		}
	}
	if err := xml.Unmarshal([]byte(strings.Replace(x, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)), new(struct{})); err != nil {
		t.Fatal(err)
	}
}

// Обобщение задачи не изменило агента уведомлений.
func TestNotifyTaskStillRunsAgent(t *testing.T) {
	if x := userTaskXML(`C:\x.exe`, "notify-agent", "описание"); !strings.Contains(x, "<Arguments>notify-agent</Arguments>") {
		t.Fatal(x)
	}
}
