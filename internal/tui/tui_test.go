package tui

import (
	"bytes"
	"strings"
	"testing"
)

var menu = []string{"Добавить приложение", "Убрать приложение", "Статус", "Журнал"}

func pick(t *testing.T, input string, items []string, o Options) (int, string) {
	t.Helper()
	var out bytes.Buffer
	i, err := Select(strings.NewReader(input), &out, items, o)
	if err != nil {
		t.Fatal(err)
	}
	return i, out.String()
}

func TestArrowsAndEnter(t *testing.T) {
	for input, want := range map[string]int{
		"\r":                               0,
		"\x1b[B\r":                         1,
		"\x1b[B\x1b[B\x1b[B\r":             3,
		"\x1b[B\x1b[B\x1b[B\x1b[B\x1b[B\r": 3, // ниже последнего — остаётся последний
		"\x1b[A\r":                         0, // выше первого — остаётся первый
		"\x1bOB\r":                         1, // стрелки в режиме приложения
		"\x1b[6~\r":                        3, // страница вниз
		"\x1b[B\x1b[B\x1b[5~\r":            0, // страница вверх
		"\x1b[B\x1b[Z\r":                   1, // незнакомая последовательность ничего не ломает
		"\n":                               0,
	} {
		if got, _ := pick(t, input, menu, Options{}); got != want {
			t.Errorf("%q: %d, ждали %d", input, got, want)
		}
	}
}

func TestBack(t *testing.T) {
	for _, input := range []string{"q", "\x03", "\x04", ""} {
		if got, _ := pick(t, input, menu, Options{}); got != -1 {
			t.Errorf("%q: %d, ждали -1", input, got)
		}
	}
}

func TestFilterNarrowsAndReturnsOriginalIndex(t *testing.T) {
	apps := []string{"Discord", "Figma", "Notion", "Notion Calendar", "Telegram"}
	if got, _ := pick(t, "not\x1b[B\r", apps, Options{Filter: true}); got != 3 {
		t.Fatalf("«not» и вниз: %d", got)
	}
	if got, _ := pick(t, "FIG\r", apps, Options{Filter: true}); got != 1 {
		t.Fatalf("регистр не важен: %d", got)
	}
	// «q» в режиме поиска — буква, а не выход.
	if got, _ := pick(t, "q\x7f\x7fte\r", apps, Options{Filter: true}); got != 4 {
		t.Fatalf("q и стирание: %d", got)
	}
	if got, _ := pick(t, "нет такого\r\x03", apps, Options{Filter: true}); got != -1 {
		t.Fatalf("Enter без совпадений: %d", got)
	}
}

func TestLongListScrolls(t *testing.T) {
	var items []string
	for i := range 40 {
		items = append(items, strings.Repeat("x", i+1))
	}
	got, out := pick(t, strings.Repeat("\x1b[B", 30)+"\r", items, Options{Title: "Приложения"})
	if got != 30 {
		t.Fatalf("%d", got)
	}
	if !strings.Contains(out, "ещё") || !strings.Contains(out, "Приложения") {
		t.Fatalf("нет подсказок прокрутки:\n%q", out[len(out)-400:])
	}
	if strings.Count(out, "\x1b[?25h") != 1 {
		t.Fatal("курсор не вернули")
	}
}

func TestEmptyListReturnsBack(t *testing.T) {
	if got, _ := pick(t, "\r", nil, Options{}); got != -1 {
		t.Fatalf("%d", got)
	}
}
