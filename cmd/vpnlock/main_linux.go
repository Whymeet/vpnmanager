package main

import (
	"log"
	"net"
	"os"
	"time"

	"vpnlock/internal/apps"
	"vpnlock/internal/cli"
	"vpnlock/internal/enforce"
	"vpnlock/internal/install"
	"vpnlock/internal/paths"
	"vpnlock/internal/service"
	"vpnlock/internal/sysdns"
)

// setupDir — папка установочных скриптов этой системы в клоне.
const setupDir = "linux"

func installer(L paths.Layout) *install.Installer {
	return &install.Installer{Layout: L, Systemd: install.Systemctl{}, Agent: sudoAgent(), Preflight: enforce.Preflight}
}

func enforcer(L paths.Layout) enforce.Enforcer {
	return &enforce.NFT{ClosedFile: L.ClosedRules, Logf: log.Printf}
}

// answers — ответы DNS на Linux не слушаются: приложение закрыто по своим
// процессам, учить его домены незачем.
func answers() service.Answers { return nil }

// notifySocket — куда сказать systemd о готовности. Из окружения адрес убирается:
// иначе его унаследуют программы, которые запускает служба, а systemd принимает
// сообщения только от неё самой.
var notifySocket = func() string {
	s := os.Getenv("NOTIFY_SOCKET")
	os.Unsetenv("NOTIFY_SOCKET")
	return s
}()

// ready говорит systemd, что правила стоят: только после этого поднимается сеть.
func ready() { tellSystemd("READY=1") }

// aliveEvery — часто говорить незачем: WatchdogSec в описании службы — минута.
const aliveEvery = 10 * time.Second

// lastAlive — когда systemd слышал о службе последний раз.
var lastAlive time.Time

// alive вызывается из цикла сторожа. Цикл встал — сообщения прекращаются, и systemd
// перезапускает службу: её перехват запусков иначе держал бы и чужие программы.
func alive() {
	if time.Since(lastAlive) >= aliveEvery {
		lastAlive = time.Now()
		tellSystemd("WATCHDOG=1")
	}
}

func tellSystemd(msg string) {
	if notifySocket == "" {
		return
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: notifySocket, Net: "unixgram"})
	if err != nil {
		log.Printf("systemd: %v", err)
		return
	}
	defer c.Close()
	if _, err := c.Write([]byte(msg)); err != nil {
		log.Printf("systemd: %v", err)
	}
}

// installNote добавляет к итогу установки то, что без systemd-resolved работает
// иначе.
func installNote(note string) string {
	if sysdns.Active() && sysdns.Stub() {
		return note
	}
	const noDNS = "systemd-resolved не работает или программы его не спрашивают (в /etc/resolv.conf нет 127.0.0.53): приложения защищены полностью, а домены сайтов (vpnlock protect <домен>) закрываются только по адресам из каталога."
	if note == "" {
		return noDNS
	}
	return note + "\n" + noDNS
}

// platformCLI — службы systemd среди того, что можно защитить.
func platformCLI(env *cli.Env) {
	env.FindService = apps.FindService
	env.SameProgram = apps.SameProgram
	env.Moved = apps.Moved
}
