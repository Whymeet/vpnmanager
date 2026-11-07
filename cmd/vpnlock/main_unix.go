//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"vpnlock/internal/accounts"
	"vpnlock/internal/apps"
	"vpnlock/internal/cli"
	"vpnlock/internal/exitcheck"
	"vpnlock/internal/install"
	"vpnlock/internal/netwatch"
	"vpnlock/internal/notify"
	"vpnlock/internal/paths"
	"vpnlock/internal/procs"
	"vpnlock/internal/service"
	"vpnlock/internal/sysdns"
	"vpnlock/internal/version"
)

// dnsAddr — где слушает резолвер службы. Порт не 53: на нём часто уже сидит
// локальный DNS VPN-клиента.
var dnsAddr = netip.MustParseAddrPort("127.0.0.1:53535")

// platform — то, что клиент делает по-своему на macOS и Linux: права root через
// sudo, список приложений, установка службой launchd или systemd.
func platform(env *cli.Env) {
	L := env.Layout
	inst := installer(L)
	env.Root = os.Geteuid() == 0
	env.Home = home()
	env.Install = func() (string, error) {
		src, err := self()
		if err != nil {
			return "", err
		}
		err = inst.Install(src)
		return installNote(inst.Note), err
	}
	env.Update = update
	// Снятие с паролем идёт мимо службы, поэтому правила файрвола и резолверы
	// снимает установка, от root, — в нужный момент.
	inst.Clear = func() error { return errors.Join(enforcer(L).Clear(), sysdns.System(dnsAddr).Clear()) }
	env.Uninstall = inst.Uninstall
	platformCLI(env)
}

// update собирает vpnlock в клоне от имени того, кто вызвал sudo: сборка от
// root испортила бы кэш Go в .toolchain клона. Потом собранный vpnlock ставит
// себя сам, как на шаге установки, — с теми же настройками.
func update(clone string) error {
	acc := sudoAgent()
	if acc == nil {
		return errors.New("запусти через sudo из своей учётной записи: собирается vpnlock от твоего имени")
	}
	u, err := user.LookupId(strconv.Itoa(acc.UID))
	if err != nil {
		return err
	}
	prep := exec.Command(filepath.Join(clone, "setup", setupDir, "prepare.sh"), "--update")
	prep.Dir = clone
	prep.Env = []string{"HOME=" + acc.Home, "USER=" + u.Username, "LOGNAME=" + u.Username, "LANG=en_US.UTF-8",
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin"}
	prep.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(acc.UID), Gid: uint32(acc.GID)}}
	prep.Stdout, prep.Stderr = os.Stdout, os.Stderr
	if err := prep.Run(); err != nil {
		return fmt.Errorf("подготовка не прошла: %w", err)
	}
	inst := exec.Command(filepath.Join(clone, "bin", "vpnlock"), "install")
	inst.Stdin, inst.Stdout, inst.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := inst.Run(); err != nil {
		return fmt.Errorf("новая версия не встала: %w", err)
	}
	return nil
}

// daemon — режим службы. Его запускает launchd или systemd от root.
func daemon(L paths.Layout) int {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	if os.Geteuid() != 0 {
		logger.Print("служба работает от root — её запускает система")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	err := service.Run(ctx, service.Deps{
		Layout:       L,
		Version:      version.Version,
		Accounts:     accounts.System{},
		Installation: installer(L),
		Network:      netwatch.Observer{},
		Fetch:        exitcheck.Bound{Timeout: 3 * time.Second},
		Enforce:      enforcer(L),
		Upstreams:    upstreams(),
		Apps:         procs.System{},
		Answers:      answers(),
		ReadApp:      apps.Read,
		PhysicalAddr: physicalAddr,
		ScanEvery:    scanEvery,
		LearnFor:     learnFor,
		RemindEvery:  30 * time.Minute,
		SystemDNS:    sysdns.System(dnsAddr),
		Notify:       notify.Console{},
		Reach:        exitcheck.Reach,
		DNSAddr:      dnsAddr.String(),
		CheckEvery:   checkEvery,
		ProbeEvery:   time.Minute,
		GuardEvery:   time.Second,
		Physical:     physicalTunnel,
		Now:          time.Now,
		Ready:        ready,
		Alive:        alive,
		Logf:         logger.Printf,
	})
	if err != nil {
		logger.Printf("служба не запустилась: %v", err)
		return 1
	}
	return 0
}

// sudoAgent — кому ставить ежедневную задачу каталога: тому, кто вызвал sudo.
// Не через sudo — некому.
func sudoAgent() *install.Agent {
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" || os.Geteuid() != 0 {
		return nil
	}
	acc, err := user.Lookup(name)
	if err != nil {
		return nil
	}
	uid, err1 := strconv.Atoi(acc.Uid)
	gid, err2 := strconv.Atoi(acc.Gid)
	if err1 != nil || err2 != nil {
		return nil
	}
	return &install.Agent{UID: uid, GID: gid, Home: acc.HomeDir}
}

// home — домашний каталог человека за терминалом: под sudo — того, кто
// вызвал sudo.
func home() string {
	if u := os.Getenv("SUDO_USER"); u != "" && os.Geteuid() == 0 {
		if acc, err := user.Lookup(u); err == nil {
			return acc.HomeDir
		}
	}
	h, _ := os.UserHomeDir()
	return h
}
