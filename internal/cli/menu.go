package cli

import (
	"bufio"
	"fmt"

	"appguard/internal/tui"
)

// menu — `appguard` без аргументов: пункты выбираются стрелками, после каждого
// действия — снова меню. Каждое действие есть и отдельной командой.
func menu(env Env) int {
	items := []struct {
		label string
		run   func(Env) int
	}{
		{"Добавить приложение", func(e Env) int { return addApp(e, nil) }},
		{"Убрать приложение", func(e Env) int { return removeApp(e, nil) }},
		{"Статус", status},
		{"Проверка", check},
		{"Журнал", followJournal},
		{"Правило", func(e Env) int { return rule(e, nil) }},
		{"Запомнить текущий выход", func(e Env) int { return remember(e, nil) }},
		{"Забыть выход", func(e Env) int { return forget(e, nil) }},
		{"Уведомления", func(e Env) int { return notifications(e, nil) }},
		{"Обновить", func(e Env) int { return update(e, nil) }},
		{"Удалить инструмент", func(e Env) int { return uninstall(e, nil) }},
		{"Выход", nil},
	}
	labels := make([]string, len(items))
	for i, it := range items {
		labels[i] = it.label
	}
	in := bufio.NewReader(env.In) // тот же буфер, что завёл Run
	for {
		fmt.Fprintln(env.Out)
		i, ok := choose(env, labels, tui.Options{Title: header(env)})
		if !ok || items[i].run == nil {
			return 0
		}
		fmt.Fprintf(env.Out, "— %s —\n", items[i].label)
		items[i].run(env)
		if items[i].label == "Удалить инструмент" && !installed(env.Layout) {
			return 0 // инструмента больше нет — и меню тоже
		}
		fmt.Fprint(env.Out, "\nEnter — назад в меню ")
		in.ReadString('\n')
	}
}

// header — строка над меню: работает ли служба и что с VPN.
func header(env Env) string {
	st, ok := statusQuiet(env)
	switch {
	case !ok && !installed(env.Layout):
		return "appguard не установлен"
	case !ok:
		// Правила файрвола живут в ядре, а не в службе: пока её нет, сервисы
		// закрыты, и система её перезапускает.
		return "appguard — служба не отвечает — защита держится"
	}
	line := "appguard " + st.Version + " — служба работает"
	switch len(st.Paths) {
	case 0:
		line += ", VPN нет"
	default:
		line += ", VPN: " + pathLabel(st.Paths[0]) + " — " + st.Paths[0].Summary
	}
	return line
}
