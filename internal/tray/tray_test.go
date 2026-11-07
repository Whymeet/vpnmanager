package tray

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const tick = 5 * time.Millisecond

// fakeIcon записывает показы вместо настоящего значка.
type fakeIcon struct {
	mu      sync.Mutex
	on      bool
	shows   int
	hides   int
	showErr error
	dies    error // показ встаёт и тут же падает
	died    chan error
}

func (f *fakeIcon) Show() (<-chan error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shows++
	if f.showErr != nil {
		return nil, f.showErr
	}
	f.died = make(chan error, 1)
	if f.dies != nil {
		f.died <- f.dies
		return f.died, nil
	}
	f.on = true
	return f.died, nil
}

func (f *fakeIcon) Hide() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hides++
	f.on = false
}

// crash ломает показ снаружи.
func (f *fakeIcon) crash(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.on = false
	f.died <- err
}

func (f *fakeIcon) state() (on bool, shows, hides int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.on, f.shows, f.hides
}

// stand — цикл с управляемой службой.
type stand struct {
	mu        sync.Mutex
	alive     bool
	polls     int
	installed bool
	icon      *fakeIcon
	logs      []string
	done      chan struct{}
	stop      context.CancelFunc
}

func start(t *testing.T, s *stand) *stand {
	t.Helper()
	if s.icon == nil {
		s.icon = &fakeIcon{}
	}
	s.installed = true
	s.done = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = cancel
	go func() {
		defer close(s.done)
		Loop{
			Icon: s.icon,
			Alive: func() bool {
				s.mu.Lock()
				defer s.mu.Unlock()
				s.polls++
				return s.alive
			},
			Installed: func() bool {
				s.mu.Lock()
				defer s.mu.Unlock()
				return s.installed
			},
			Every: tick,
			Logf: func(format string, args ...any) {
				s.mu.Lock()
				defer s.mu.Unlock()
				s.logs = append(s.logs, format)
			},
		}.Run(ctx)
	}()
	// Цикл без пауз контекста не видит: тест должен упасть, а не повиснуть вместе с ним.
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.done:
		case <-time.After(2 * time.Second):
			t.Error("цикл не остановился")
		}
	})
	return s
}

func (s *stand) set(alive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alive = alive
}

func (s *stand) waitPolls(n int) {
	s.mu.Lock()
	want := s.polls + n
	s.mu.Unlock()
	for {
		s.mu.Lock()
		got := s.polls
		s.mu.Unlock()
		if got >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); !ok(); {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestIconAppearsOnFirstReply(t *testing.T) {
	s := start(t, &stand{})
	s.waitPolls(3)
	if on, shows, _ := s.icon.state(); on || shows != 0 {
		t.Fatal("значок показан раньше ответа службы")
	}
	s.set(true)
	eventually(t, "значок не появился", func() bool { on, _, _ := s.icon.state(); return on })
}

// Одна-две неудачи подряд значок не гасят: это таймаут под нагрузкой. Третья гасит.
func TestIconHidesAfterThreeFailuresInARow(t *testing.T) {
	var (
		mu      sync.Mutex
		replies = []bool{true, false, false, true, false, false, false, false}
		at      int
		seen    []bool
	)
	icon := &fakeIcon{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Loop{
			Icon: icon,
			Alive: func() bool {
				mu.Lock()
				defer mu.Unlock()
				on, _, _ := icon.state()
				seen = append(seen, on) // каким значок был перед этим опросом
				if at == len(replies) {
					cancel()
					return false
				}
				at++
				return replies[at-1]
			},
			Installed: func() bool { return true },
			Every:     tick,
			Logf:      func(string, ...any) {},
		}.Run(ctx)
	}()
	<-done
	// Первый опрос — до значка; дальше значок держится до третьей неудачи подряд.
	want := []bool{false, true, true, true, true, true, true, false, false}
	if len(seen) != len(want) {
		t.Fatalf("опросы: %v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("после опроса %d значок %v, ждали %v: %v", i, seen[i], want[i], seen)
		}
	}
	if _, shows, hides := icon.state(); shows != 1 || hides != 1 {
		t.Fatalf("показов %d, скрытий %d", shows, hides)
	}
}

func TestIconReturnsWithTheService(t *testing.T) {
	s := start(t, &stand{alive: true})
	eventually(t, "значок не появился", func() bool { on, _, _ := s.icon.state(); return on })
	s.set(false)
	eventually(t, "значок не скрылся", func() bool { on, _, _ := s.icon.state(); return !on })
	s.set(true)
	eventually(t, "значок не вернулся", func() bool { on, _, _ := s.icon.state(); return on })
	if _, shows, hides := s.icon.state(); shows != 2 || hides != 1 {
		t.Fatalf("показов %d, скрытий %d", shows, hides)
	}
}

func TestBrokenIconRisesAgain(t *testing.T) {
	s := start(t, &stand{alive: true})
	eventually(t, "значок не появился", func() bool { on, _, _ := s.icon.state(); return on })
	s.icon.crash(errors.New("показ упал"))
	eventually(t, "значок не поднялся", func() bool { on, shows, _ := s.icon.state(); return on && shows == 2 })
}

// Показ, который ломается сразу, поднимается раз в тик, а не в цикле без пауз, и
// причину пишет один раз.
func TestBrokenIconDoesNotSpin(t *testing.T) {
	for name, icon := range map[string]*fakeIcon{
		"не встаёт":       {showErr: errors.New("показ не встаёт")},
		"встаёт и падает": {dies: errors.New("показ упал")},
	} {
		t.Run(name, func(t *testing.T) {
			began := time.Now()
			s := start(t, &stand{alive: true, icon: icon})
			time.Sleep(20 * tick)
			_, shows, _ := icon.state()
			if shows < 2 {
				t.Fatalf("показ не повторяется: %d", shows)
			}
			if limit := int(time.Since(began)/tick) + 1; shows > limit {
				t.Fatalf("показов %d, а тиков было %d: цикл без пауз", shows, limit)
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if len(s.logs) != 1 {
				t.Fatalf("причина записана %d раз", len(s.logs))
			}
		})
	}
}

func TestLoopLeavesWhenVpnlockIsRemoved(t *testing.T) {
	s := start(t, &stand{alive: true})
	eventually(t, "значок не появился", func() bool { on, _, _ := s.icon.state(); return on })
	s.mu.Lock()
	s.alive, s.installed = false, false
	s.mu.Unlock()
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		t.Fatal("цикл не вышел после удаления")
	}
	if on, _, _ := s.icon.state(); on {
		t.Fatal("значок остался после удаления")
	}
}

func TestLoopHidesIconOnStop(t *testing.T) {
	s := start(t, &stand{alive: true})
	eventually(t, "значок не появился", func() bool { on, _, _ := s.icon.state(); return on })
	s.stop()
	<-s.done
	if on, _, _ := s.icon.state(); on {
		t.Fatal("значок остался после остановки")
	}
}

func TestLoopLeavesWithoutSession(t *testing.T) {
	s := start(t, &stand{alive: true, icon: &fakeIcon{showErr: ErrNoSession}})
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		t.Fatal("цикл ждёт сеанс, которого нет")
	}
}

// Сеанс кончился, пока значок был показан: значок выходит, а не стучится в новый сеанс.
func TestLoopLeavesWhenSessionEnds(t *testing.T) {
	s := start(t, &stand{alive: true})
	eventually(t, "значок не появился", func() bool { on, _, _ := s.icon.state(); return on })
	s.icon.crash(ErrNoSession)
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		t.Fatal("цикл не вышел после конца сеанса")
	}
	if _, shows, _ := s.icon.state(); shows != 1 {
		t.Fatalf("показов %d", shows)
	}
}

func TestShieldIsReadableOnAnyPanel(t *testing.T) {
	for _, size := range []int{16, 20, 24, 32, 64} {
		img := shield(size)
		if img.Bounds().Dx() != size || img.Bounds().Dy() != size {
			t.Fatalf("%d: %v", size, img.Bounds())
		}
		if img.NRGBAAt(0, 0).A != 0 {
			t.Errorf("%d: угол не прозрачный", size)
		}
		var white, green, dark int
		for y := range size {
			for x := range size {
				c := img.NRGBAAt(x, y)
				switch {
				case c.A < 200:
				case c.R > 200 && c.G > 200 && c.B > 200:
					white++ // кайма и скважина: видны на тёмной панели
				case c.G > c.R+40 && c.G > c.B+40 && c.G > 100:
					green++ // щит
				case c.G < 120:
					dark++ // внешняя кайма: видна на светлой панели
				}
			}
		}
		if white == 0 || green == 0 {
			t.Errorf("%d: белых пикселей %d, зелёных %d", size, white, green)
		}
		if size == 64 && dark == 0 {
			t.Error("нет тёмной каймы")
		}
	}
	if !strings.HasPrefix(string(shieldPNG), "\x89PNG") {
		t.Fatal("shield.png — не PNG")
	}
}
