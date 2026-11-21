package main

import (
	"context"
	"testing"

	"golang.org/x/sys/windows/svc"

	"appguard/internal/paths"
)

// execute гоняет обработчик службы без диспетчера служб: шлёт команды cmds и
// возвращает код выхода.
func execute(cmds ...svc.Cmd) uint32 {
	h := &handler{
		run:  func(ctx context.Context) error { <-ctx.Done(); return nil },
		logf: func(string, ...any) {},
	}
	req := make(chan svc.ChangeRequest)
	status := make(chan svc.Status, 16)
	go func() {
		for _, c := range cmds {
			req <- svc.ChangeRequest{Cmd: c}
		}
	}()
	_, code := h.Execute(nil, req, status)
	return code
}

// К22: службу остановили не через appguard — она выходит с ошибкой, и диспетчер
// служб запускает её снова. Обновление и удаление предупреждают заранее.
func TestForeignStopRestartsTheService(t *testing.T) {
	if code := execute(svc.Stop); code == 0 {
		t.Fatal("чужая остановка вышла без ошибки — диспетчер служб службу не перезапустит")
	}
	if code := execute(svc.Cmd(paths.PlannedStop), svc.Stop); code != 0 {
		t.Fatalf("остановка от appguard вышла с кодом %d", code)
	}
	if code := execute(svc.Shutdown); code != 0 {
		t.Fatalf("выключение компьютера вышло с кодом %d", code)
	}
}
