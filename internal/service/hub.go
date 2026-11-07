package service

import "sync"

// hub раздаёт уведомления тем, кто подписан по каналу службы: на Windows их
// показывает задача в сеансе пользователя — у службы своего сеанса нет.
type hub struct {
	mu   sync.Mutex
	subs map[chan string]bool
}

// subscribe — новые уведомления, пока не вызван cancel.
func (h *hub) subscribe() (<-chan string, func()) {
	ch := make(chan string, 8)
	h.mu.Lock()
	if h.subs == nil {
		h.subs = map[chan string]bool{}
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
func (h *hub) publish(text string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- text:
		default:
		}
	}
}
