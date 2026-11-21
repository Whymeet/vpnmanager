package cli

import (
	"fmt"
	"os"

	"appguard/internal/catalog"
	"appguard/internal/core"
	"appguard/internal/ipc"
)

// importBatch — сколько доменов и адресов идёт службе одним запросом: запрос
// не больше 64 КБ.
const importBatch = 500

// importFile — `appguard import <файл>`: всё из файла закрывается сразу, вне
// проверенного VPN, как через protect. Файл — выгрузка appguard catalog export
// с другого компьютера или список доменов и адресов.
func importFile(env Env, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(env.Err, "Укажи файл: appguard import <файл> — выгрузка appguard catalog export или список доменов и адресов, по одному на строку.")
		return 2
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(env.Err, "Файл не читается: %v\n", err)
		return 1
	}
	if len(data) > 1<<20 {
		fmt.Fprintln(env.Err, "Файл больше 1 МБ — это не список адресов.")
		return 1
	}
	domains, addrs, warnings, err := catalog.ParseList(data)
	if err != nil {
		fmt.Fprintf(env.Err, "Файл не разобран: %v\n", err)
		return 1
	}
	if len(domains)+len(addrs) == 0 {
		fmt.Fprintln(env.Err, "В файле нет ни доменов, ни адресов.")
		printDropped(env, warnings)
		return 1
	}
	var got ipc.Imported
	for i := 0; i < len(domains)+len(addrs); i += importBatch {
		req := ipc.Request{Cmd: ipc.CmdImport}
		for j := i; j < min(i+importBatch, len(domains)+len(addrs)); j++ {
			if j < len(domains) {
				req.Domains = append(req.Domains, domains[j])
			} else {
				req.Addrs = append(req.Addrs, addrs[j-len(domains)])
			}
		}
		resp, err := ipc.Call(env.Layout.Socket, req)
		if err != nil {
			return silent(env, err)
		}
		warnings = append(warnings, resp.Warnings...)
		if !resp.OK {
			fmt.Fprintln(env.Err, resp.Error)
			printDropped(env, warnings)
			return 1
		}
		got.Domains += resp.Imported.Domains
		got.Addrs += resp.Imported.Addrs
	}
	fmt.Fprintf(env.Out, "Защищено сразу: %d %s и %d %s — без проверенного VPN они закрыты.\n",
		got.Domains, core.Plural(got.Domains, "домен", "домена", "доменов"), got.Addrs, core.Plural(got.Addrs, "адрес", "адреса", "адресов"))
	if already := len(domains) + len(addrs) - len(warnings) - got.Domains - got.Addrs; already > 0 {
		fmt.Fprintf(env.Out, "Ещё %d из файла уже были под защитой.\n", already)
	}
	printDropped(env, warnings)
	return 0
}

func printDropped(env Env, warnings []string) {
	for _, w := range warnings {
		fmt.Fprintf(env.Out, "  отброшено: %s\n", w)
	}
}
