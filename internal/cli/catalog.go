package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"vpnlock/internal/catalog"
	"vpnlock/internal/ipc"
)

// defaultCatalog — каталог в клоне, из которого запущена команда.
const defaultCatalog = catalog.InClone

// catalogCmd — «catalog load», «catalog export» и «catalog sync».
func catalogCmd(env Env, args []string) int {
	if len(args) == 0 || len(args) > 2 {
		fmt.Fprintln(env.Err, "Нужно: vpnlock catalog load [файл] или vpnlock catalog export [файл]")
		return 2
	}
	if args[0] == "sync" {
		clone := "."
		if len(args) == 2 {
			clone = args[1]
		}
		return syncCatalog(env, clone)
	}
	file := defaultCatalog
	if len(args) == 2 {
		file = args[1]
	}
	switch args[0] {
	case "load":
		return loadCatalog(env, file)
	case "export":
		return exportCatalog(env, file)
	}
	fmt.Fprintf(env.Err, "У каталога нет действия «%s»: load, export или sync.\n", args[0])
	return 2
}

// loadCatalog отдаёт службе каталог из файла.
func loadCatalog(env Env, file string) int {
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(env.Err, "Файл каталога не читается: %v. Запусти команду из клона репозитория или укажи путь.\n", err)
		return 1
	}
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdCatalog, Catalog: data})
	if err != nil {
		return silent(env, err)
	}
	if !resp.OK {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	for _, w := range resp.Warnings {
		fmt.Fprintf(env.Out, "  отброшено: %s\n", w)
	}
	fmt.Fprintln(env.Out, "Каталог загружен в службу.")
	return 0
}

// exportCatalog — у автора: вносит выученное на этом маке в файл каталога
// клона и показывает, что добавлено и что отброшено. Дальше — обычная
// публикация курса.
func exportCatalog(env Env, file string) int {
	cur := catalog.Catalog{Format: catalog.Format, Apps: []catalog.App{}}
	data, err := os.ReadFile(file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if _, err := os.Stat(filepath.Dir(file)); err != nil {
			fmt.Fprintf(env.Err, "Нет каталога %s: запусти команду из клона репозитория vpnlock или укажи файл.\n", filepath.Dir(file))
			return 1
		}
	case err != nil:
		fmt.Fprintf(env.Err, "Файл каталога не читается: %v\n", err)
		return 1
	default:
		if cur, _, err = catalog.Parse(data); err != nil {
			fmt.Fprintf(env.Err, "Каталог %s не разобран: %v. Выгрузка его не трогает.\n", file, err)
			return 1
		}
	}
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdExport})
	if err != nil {
		return silent(env, err)
	}
	if !resp.OK {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	if len(resp.Learned) == 0 {
		fmt.Fprintln(env.Out, "На этом маке ещё нет обученных приложений — выгружать нечего.")
		return 0
	}
	next, rep := catalog.Merge(cur, resp.Learned, time.Now().Format("2006-01-02"))
	rep.Drops = append(resp.Dropped, rep.Drops...)
	out, err := catalog.Marshal(next)
	if err != nil {
		fmt.Fprintln(env.Err, err)
		return 1
	}
	if len(rep.Changes) > 0 {
		if err := os.WriteFile(file, out, 0o644); err != nil {
			fmt.Fprintf(env.Err, "Каталог не записан: %v\n", err)
			return 1
		}
	}
	printReport(env, file, rep)
	return 0
}

func printReport(env Env, file string, rep catalog.Report) {
	if len(rep.Changes) == 0 {
		fmt.Fprintf(env.Out, "В %s уже есть всё выученное на этом маке — файл не изменён.\n", file)
	} else {
		fmt.Fprintf(env.Out, "Добавлено в %s:\n", file)
		for _, c := range rep.Changes {
			var parts []string
			if c.New {
				parts = append(parts, "новое приложение")
			}
			own := slices.DeleteFunc(slices.Clone(c.Domains), func(d string) bool { return slices.Contains(c.Exact, d) })
			if len(own) > 0 {
				parts = append(parts, "домены "+strings.Join(own, ", "))
			}
			if len(c.Exact) > 0 {
				parts = append(parts, "сторонние точным именем "+strings.Join(c.Exact, ", "))
			}
			if len(c.Addrs) > 0 {
				parts = append(parts, "адреса "+strings.Join(c.Addrs, ", "))
			}
			fmt.Fprintf(env.Out, "  %s: %s\n", c.App, strings.Join(parts, "; "))
		}
	}
	if len(rep.Drops) > 0 {
		fmt.Fprintln(env.Out, "Отброшено — в каталог это не попало:")
		for _, d := range rep.Drops {
			fmt.Fprintf(env.Out, "  %s: %s — %s\n", d.App, d.Value, d.Why)
		}
	}
	if len(rep.Changes) > 0 {
		fmt.Fprintf(env.Out, "Дальше — обычная публикация курса: посмотри git diff %s и закоммить.\n", file)
	}
}

func dayText(day string) string {
	if t, err := time.Parse("2006-01-02", day); err == nil {
		return "от " + t.Format("02.01.2006")
	}
	return "без даты"
}
