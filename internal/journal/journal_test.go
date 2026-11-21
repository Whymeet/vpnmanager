package journal

import (
	"os"
	"testing"
	"time"

	"appguard/internal/core"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestEventsOlderThanAWeekAreDeleted(t *testing.T) {
	dir := t.TempDir()
	c := &clock{time.Date(2026, 10, 1, 12, 0, 0, 0, time.Local)}
	j, err := Open(dir, c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()

	for d := 0; d < 10; d++ { // по событию в день: 1–10 октября
		c.t = time.Date(2026, 10, 1+d, 12, 0, 0, 0, time.Local)
		if err := j.Add(core.Event{Time: c.t, Text: c.t.Format("02.01")}); err != nil {
			t.Fatal(err)
		}
	}

	recent, _, stop := j.Follow(100)
	stop()
	if len(recent) != 8 || recent[0].Text != "03.10" || recent[7].Text != "10.10" {
		t.Fatalf("10 октября в журнале должны быть события за неделю (3–10 октября), а там %v", texts(recent))
	}
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		if f.Name() < "2026-10-02" {
			t.Fatalf("файл %s старше недели не удалён", f.Name())
		}
	}
}

func TestFollowGetsNewEvents(t *testing.T) {
	c := &clock{time.Now()}
	j, err := Open(t.TempDir(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	j.Add(core.Event{Time: c.t, Text: "раньше"})

	recent, live, stop := j.Follow(10)
	defer stop()
	if len(recent) != 1 || recent[0].Text != "раньше" {
		t.Fatalf("последние события: %v", texts(recent))
	}
	j.Add(core.Event{Time: c.t, Text: "сейчас"})
	select {
	case e := <-live:
		if e.Text != "сейчас" {
			t.Fatalf("пришло %q", e.Text)
		}
	case <-time.After(time.Second):
		t.Fatal("новое событие не пришло")
	}
}

func texts(es []core.Event) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Text
	}
	return out
}
