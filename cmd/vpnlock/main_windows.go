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
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"vpnlock/internal/accounts"
	"vpnlock/internal/apps"
	"vpnlock/internal/cli"
	"vpnlock/internal/dnswatch"
	"vpnlock/internal/enforce"
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

// dnsAddr — где слушает резолвер службы. Порт — 53: другого правила NRPT не
// знают. Адрес — отдельный адрес петли: на 127.0.0.1:53 часто уже сидит DNS
// клиента VPN.
var dnsAddr = netip.MustParseAddrPort("127.53.53.53:53")

// platform — то, что клиент делает по-своему на Windows: права — запуск от
// имени администратора, установка — служба Windows.
func platform(env *cli.Env) {
	// Удаление снимает фильтры WFP и правила NRPT само, от имени
	// администратора: служба к этому времени остановлена.
	inst := &install.Installer{Layout: env.Layout, Clear: func() error {
		return errors.Join(wfp(env.Layout, nil).Clear(), sysdns.System(dnsAddr).Clear())
	}}
	env.Root = elevated()
	env.Toast = notify.Toast
	env.Home, _ = os.UserHomeDir()
	env.Install = func() (string, error) {
		src, err := self()
		if err != nil {
			return "", err
		}
		err = inst.Install(src)
		return inst.Note, err
	}
	env.Uninstall = inst.Uninstall
	env.Update = update
}

// update собирает vpnlock в клоне подготовкой — от имени того же человека, в
// том же окне — и ставит собранное, как на шаге установки, с теми же
// настройками.
func update(clone string) error {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	prep := exec.Command(ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
		filepath.Join(clone, "setup", "windows", "prepare.ps1"), "-ForUpdate")
	prep.Dir = clone
	prep.Stdout, prep.Stderr = os.Stdout, os.Stderr
	if err := prep.Run(); err != nil {
		return fmt.Errorf("подготовка не прошла: %w", err)
	}
	inst := exec.Command(filepath.Join(clone, "bin", "vpnlock.exe"), "install")
	inst.Stdin, inst.Stdout, inst.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := inst.Run(); err != nil {
		return fmt.Errorf("новая версия не встала: %w", err)
	}
	return nil
}

// elevated — программа запущена от имени администратора: группа
// администраторов в её маркере доступа включена, а не только запрещающая.
func elevated() bool {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	ok, err := windows.Token(0).IsMember(admins)
	return err == nil && ok
}

// daemon — режим службы. Его запускает диспетчер служб Windows от имени
// LocalSystem; из консоли от имени администратора служба работает до Ctrl+C —
// так её удобно отлаживать.
func daemon(L paths.Layout) int {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	asService, err := svc.IsWindowsService()
	if err != nil {
		logger.Printf("не удалось узнать, кто запустил службу: %v", err)
		return 1
	}
	if asService {
		// Консоли у службы нет: её вывод — в файл рядом с журналом.
		if f, err := os.OpenFile(L.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			defer f.Close()
			logger.SetOutput(f)
		}
	}
	if !elevated() {
		logger.Print("служба работает от имени системы — её запускает диспетчер служб Windows")
		return 1
	}
	run := func(ctx context.Context) error { return service.Run(ctx, deps(L, logger.Printf)) }
	if !asService {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if err := run(ctx); err != nil {
			logger.Printf("служба не запустилась: %v", err)
			return 1
		}
		return 0
	}
	if err := svc.Run(paths.ServiceName, &handler{run: run, logf: logger.Printf}); err != nil {
		logger.Printf("диспетчер служб: %v", err)
		return 1
	}
	return 0
}

// handler — служба глазами диспетчера служб: стартует, отвечает на опрос и
// останавливается по его команде.
type handler struct {
	run  func(ctx context.Context) error
	logf func(format string, args ...any)
}

// plannedFor — сколько после paths.PlannedStop ждать остановки: позже она уже
// не та, о которой предупредили (свою команду может прислать и обычный
// пользователь).
const plannedFor = 30 * time.Second

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	var planned time.Time
	for {
		select {
		case err := <-done:
			// Служба вышла сама. С ошибкой код выхода не нулевой, и диспетчер
			// служб запускает её снова по правилам восстановления.
			if err != nil {
				h.logf("служба остановилась с ошибкой: %v", err)
				return false, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Cmd(paths.PlannedStop):
				planned = time.Now()
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				if err := <-done; err != nil {
					h.logf("служба остановилась с ошибкой: %v", err)
				}
				// Остановили не обновлением и не удалением — выходим с ошибкой:
				// диспетчер служб запустит службу снова (К22). Защита всё это
				// время держится на постоянных фильтрах.
				if c.Cmd == svc.Stop && time.Since(planned) > plannedFor {
					h.logf("службу остановили не через vpnlock — диспетчер служб запустит её снова")
					return false, 1
				}
				return false, 0
			}
		}
	}
}

// wfp — исполнитель правил на WFP; какие приложения под фильтрами, он помнит в
// каталоге службы.
func wfp(L paths.Layout, logf func(format string, args ...any)) *enforce.WFP {
	return &enforce.WFP{StateFile: filepath.Join(L.StateDir, "wfp.json"), Logf: logf}
}

// deps — адаптеры службы на Windows. Те, которых ещё нет, — заглушки из
// pending_windows.go.
func deps(L paths.Layout, logf func(format string, args ...any)) service.Deps {
	return service.Deps{
		Layout:       L,
		Version:      version.Version,
		Accounts:     accounts.System{},
		Installation: &install.Installer{Layout: L},
		Network:      netwatch.Observer{},
		Fetch:        exitcheck.Bound{Timeout: 3 * time.Second},
		Enforce:      wfp(L, logf),
		Upstreams:    upstreams(),
		Apps:         procs.System{},
		Answers:      dnswatch.System{},
		ReadApp:      apps.Read,
		PhysicalAddr: physicalAddr,
		ScanEvery:    scanEvery,
		LearnFor:     learnFor,
		RemindEvery:  30 * time.Minute,
		SystemDNS:    sysdns.System(dnsAddr),
		Reach:        exitcheck.Reach,
		DNSAddr:      dnsAddr.String(),
		CheckEvery:   checkEvery,
		ProbeEvery:   time.Minute,
		GuardEvery:   time.Second,
		Physical:     physicalTunnel,
		Now:          time.Now,
		Logf:         logf,
	}
}
