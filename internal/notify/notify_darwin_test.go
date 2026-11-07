package notify

import (
	"slices"
	"testing"
)

func TestNotificationRunsAsTheConsoleUserWithTextAsArgument(t *testing.T) {
	text := `Защищённые приложения без сети: выход в России (95.1.2.3)" & do shell script "rm -rf ~`
	args := command(501, text)
	if !slices.Equal(args[:5], []string{"asuser", "501", "/usr/bin/sudo", "-u", "#501"}) {
		t.Fatalf("не от имени пользователя: %q", args)
	}
	if args[len(args)-2] != text || args[len(args)-1] != Title {
		t.Fatalf("текст не последним аргументом: %q", args)
	}
	for _, a := range args[:len(args)-2] {
		if a == text {
			t.Fatal("текст попал в сам скрипт")
		}
	}
}
