//go:build live && darwin

package dnswatch

import (
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"
)

// Живая проверка: ответ DNS на интерфейсе маршрута по умолчанию слышен через
// BPF. Нужен root — собрать `tools/go test -c -tags live -o
// /tmp/appguard-dnswatch.test ./internal/dnswatch`, запустить под sudo.
func TestLiveHearsDNSAnswers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF открывает только root")
	}
	out, err := exec.Command("/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`interface: (\S+)`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("нет маршрута по умолчанию:\n%s", out)
	}
	iface := string(m[1])
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	heard := make(chan Answer, 16)
	go func() {
		if err := (System{}).Listen(ctx, iface, func(a Answer) { heard <- a }); err != nil {
			t.Errorf("слушать %s: %v", iface, err)
		}
	}()
	time.Sleep(500 * time.Millisecond)
	// Свой резолвер Go шлёт запрос на сервер из resolv.conf напрямую, мимо кэша
	// системы: ответ точно пройдёт по сети.
	r := &net.Resolver{PreferGo: true}
	if _, err := r.LookupHost(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case a := <-heard:
			t.Logf("%s: %s → %v", iface, a.Name, a.Addrs)
			if a.Name == "example.com" {
				return
			}
		case <-ctx.Done():
			t.Fatalf("ответ про example.com на %s не услышан", iface)
		}
	}
}
