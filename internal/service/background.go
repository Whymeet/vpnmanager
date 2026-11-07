package service

import (
	"context"
	"sync"
)

// background — фоновые работы движка. Они идут, пока движок работает:
// остановка прерывает их и ждёт — иначе запись в настройки легла бы уже после
// выхода службы, поверх настроек следующего её запуска.
type background struct {
	life context.Context
	stop context.CancelFunc
	mu   sync.Mutex
	wg   sync.WaitGroup
}

func newBackground() *background {
	b := &background{}
	b.life, b.stop = context.WithCancel(context.Background())
	return b
}

// Go запускает f в фоне с контекстом движка; после Stop — ничего не делает.
func (b *background) Go(f func(life context.Context)) {
	b.mu.Lock()
	if b.life.Err() != nil {
		b.mu.Unlock()
		return
	}
	b.wg.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.wg.Done()
		f(b.life)
	}()
}

// Stop прерывает фоновые работы и ждёт их.
func (b *background) Stop() {
	b.mu.Lock()
	b.stop()
	b.mu.Unlock()
	b.wg.Wait()
}
