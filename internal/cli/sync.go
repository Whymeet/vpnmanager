package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"appguard/internal/ipc"
)

// gitTimeout — сколько ждать git: fetch по медленной сети.
const gitTimeout = 2 * time.Minute

// syncCatalog — `appguard catalog sync <клон>`: ежедневная задача от имени
// ученика, без повышения. git fetch и перемотка вперёд в клоне — без слияний,
// локальные правки не трогаются; затем служба сама берёт из клона каталог и
// версию инструмента — или узнаёт, почему обновиться не вышло. Защита в любом
// случае работает на последнем каталоге, который приняла служба.
func syncCatalog(env Env, clone string) int {
	req := ipc.Request{Cmd: ipc.CmdSync}
	if abs, err := filepath.Abs(clone); err == nil {
		clone = abs
	}
	req.Problem = pull(clone)
	resp, err := callWhenUp(env, req)
	if err != nil {
		return silent(env, err)
	}
	if !resp.OK {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	if req.Problem != "" {
		fmt.Fprintf(env.Out, "%s Каталог не обновлён: %s\n", time.Now().Format("02.01 15:04"), req.Problem)
		return 1
	}
	fmt.Fprintf(env.Out, "%s Каталог сверен с репозиторием.\n", time.Now().Format("02.01 15:04"))
	return 0
}

// callWhenUp — запрос к службе; при входе в систему задача может опередить
// службу, поэтому несколько попыток.
func callWhenUp(env Env, req ipc.Request) (ipc.Response, error) {
	var resp ipc.Response
	var err error
	for range 10 {
		if resp, err = ipc.Call(env.Layout.Socket, req); !errors.Is(err, ipc.ErrNotRunning) {
			return resp, err
		}
		time.Sleep(time.Second)
	}
	return resp, err
}

// pull перематывает клон вперёд до вышестоящей ветки. Пусто — удалось (или
// перематывать нечего); иначе — почему нет, словами для журнала.
func pull(clone string) string {
	if fi, err := os.Stat(clone); err != nil || !fi.IsDir() {
		return "клон " + clone + " не найден — перемещён или удалён; переустанови appguard из нового места по setup/README.md"
	}
	git, err := gitPath()
	if err != nil {
		return err.Error()
	}
	run := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, git, append([]string{"-C", clone}, args...)...)
		// Без вопросов в терминал, без окон Git Credential Manager и без пароля
		// ssh: задача работает в фоне.
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never", "GIT_SSH_COMMAND=ssh -o BatchMode=yes", "LC_ALL=C")
		quiet(cmd)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return strings.TrimSpace(out.String()), err
	}
	if _, err := run("rev-parse", "--is-inside-work-tree"); err != nil {
		return "в " + clone + " больше нет клона git — он перемещён или удалён; переустанови appguard из нового места по setup/README.md"
	}
	if out, err := run("fetch", "--quiet"); err != nil {
		if denied(out) {
			return "доступ к репозиторию закрыт (" + firstLine(out) + ")"
		}
		return "не удалось связаться с репозиторием: " + firstLine(out)
	}
	if _, err := run("rev-parse", "--verify", "--quiet", "@{u}"); err != nil {
		return "у текущей ветки клона нет вышестоящей ветки — обновлять не из чего"
	}
	out, err := run("merge", "--ff-only", "--quiet", "@{u}")
	switch {
	case err == nil:
		return ""
	case strings.Contains(out, "Not possible to fast-forward") || strings.Contains(out, "Diverging branches"):
		return "история клона разошлась с репозиторием — обновление ничего не меняет; что в клоне, покажет git status"
	case strings.Contains(out, "local changes") || strings.Contains(out, "untracked working tree files"):
		return "в клоне правки в файлах, которые меняет обновление, — оно их не трогает и ничего не меняет"
	}
	return "git merge --ff-only: " + firstLine(out)
}

// denied — git сказал, что доступа нет: приглашение отозвано, ключ или токен
// не подходят.
func denied(out string) bool {
	for _, s := range []string{"Repository not found", "Permission denied", "Authentication failed", "could not read Username", "403", "access denied"} {
		if strings.Contains(out, s) {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimPrefix(s, "fatal: ")
}
