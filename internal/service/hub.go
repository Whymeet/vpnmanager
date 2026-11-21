package service

import (
	"sync"

	"appguard/internal/core"
)

// hub раздаёт уведомления тем, кто подписан по каналу службы: на Windows их
// показывает задача в сеансе пользователя — у службы своего сеанса нет.
type hub struct {
	mu   sync.Mutex
	subs map[chan core.Event]bool
}

// subscribe — новые уведомления, пока не вызван cancel.
func (h *hub) subscribe() (<-chan core.Event, func()) {
	ch := make(chan core.Event, 8)
	h.mu.Lock()
	if h.subs == nil {
		h.subs = map[chan core.Event]bool{}
	}
	h.subs[ch] = true
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// publish отдаёт уведомление всем подписчикам. Медленный подписчик пропускает
// лишнее, а не задерживает службу.
func (h *hub) publish(note core.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- note:
		default:
		}
	}
}
