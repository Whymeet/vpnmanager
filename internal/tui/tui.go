// Package tui — меню в терминале: пункты выбираются стрелками.
package tui

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// window — сколько пунктов видно сразу; остальное прокручивается.
const window = 14

// Options — как показывать список.
type Options struct {
	Title string
	// Filter — набор букв сужает список (для длинных списков вроде приложений).
	// Без фильтра «q» значит «назад».
	Filter bool
}

// Select показывает items и возвращает номер выбранного в items или -1, если
// человек вернулся назад (q, Ctrl+C, Ctrl+D). in — ввод терминала в
// посимвольном режиме, out — вывод.
func Select(in io.Reader, out io.Writer, items []string, o Options) (int, error) {
	if len(items) == 0 {
		return -1, nil
	}
	r := bufio.NewReader(in)
	s := &state{items: items, o: o}
	s.refilter()
	fmt.Fprint(out, "\x1b[?25l") // курсор не мигает поверх меню
	defer fmt.Fprint(out, "\x1b[?25h")
	for {
		s.draw(out)
		k, err := readKey(r)
		if err != nil {
			s.erase(out)
			if err == io.EOF {
				return -1, nil
			}
			return -1, err
		}
		switch {
		case k.name == "up":
			s.move(-1)
		case k.name == "down":
			s.move(1)
		case k.name == "pgup":
			s.move(-window)
		case k.name == "pgdn":
			s.move(window)
		case k.name == "enter":
			if len(s.shown) > 0 {
				s.erase(out)
				return s.shown[s.cur], nil
			}
		case k.name == "cancel", k.name == "rune" && k.r == 'q' && !o.Filter:
			s.erase(out)
			return -1, nil
		case k.name == "backspace" && o.Filter:
			if _, size := utf8.DecodeLastRuneInString(s.query); size > 0 {
				s.query = s.query[:len(s.query)-size]
				s.refilter()
			}
		case k.name == "rune" && o.Filter && unicode.IsPrint(k.r):
			s.query += string(k.r)
			s.refilter()
		}
	}
}

type state struct {
	items  []string
	o      Options
	query  string
	shown  []int // номера пунктов, подходящих под фильтр
	cur    int   // выбранный среди shown
	top    int   // первый видимый среди shown
	height int   // сколько строк нарисовано в прошлый раз
}

func (s *state) refilter() {
	q := strings.ToLower(s.query)
	s.shown = s.shown[:0]
	for i, it := range s.items {
		if q == "" || strings.Contains(strings.ToLower(it), q) {
			s.shown = append(s.shown, i)
		}
	}
	s.cur, s.top = 0, 0
}

func (s *state) move(d int) {
	if len(s.shown) == 0 {
		return
	}
	s.cur = max(0, min(len(s.shown)-1, s.cur+d))
	if s.cur < s.top {
		s.top = s.cur
	}
	if s.cur >= s.top+window {
		s.top = s.cur - window + 1
	}
}

func (s *state) draw(out io.Writer) {
	var b strings.Builder
	s.clear(&b)
	lines := 0
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\x1b[K\n", args...)
		lines++
	}
	if s.o.Title != "" {
		line("%s", s.o.Title)
	}
	if s.o.Filter {
		line("  Поиск: %s▏", s.query)
	}
	end := min(len(s.shown), s.top+window)
	if s.top > 0 {
		line("  … ещё %d выше", s.top)
	}
	for i := s.top; i < end; i++ {
		if i == s.cur {
			line("\x1b[7m ▸ %s \x1b[0m", s.items[s.shown[i]])
		} else {
			line("   %s", s.items[s.shown[i]])
		}
	}
	if len(s.shown) == 0 {
		line("   ничего не нашлось")
	}
	if rest := len(s.shown) - end; rest > 0 {
		line("  … ещё %d ниже", rest)
	}
	if s.o.Filter {
		line("\x1b[2m  ↑↓ — выбрать, Enter — готово, буквы — поиск, Ctrl+C — назад\x1b[0m")
	} else {
		line("\x1b[2m  ↑↓ — выбрать, Enter — готово, q — назад\x1b[0m")
	}
	s.height = lines
	fmt.Fprint(out, b.String())
}

// clear поднимается к началу прошлого кадра и стирает его.
func (s *state) clear(b *strings.Builder) {
	if s.height > 0 {
		fmt.Fprintf(b, "\x1b[%dA\r\x1b[J", s.height)
	}
}

func (s *state) erase(out io.Writer) {
	var b strings.Builder
	s.clear(&b)
	s.height = 0
	fmt.Fprint(out, b.String())
}

type key struct {
	name string // up, down, pgup, pgdn, enter, cancel, backspace, rune, other
	r    rune
}

// readKey читает одну клавишу: обычный символ или ESC-последовательность.
func readKey(r *bufio.Reader) (key, error) {
	c, _, err := r.ReadRune()
	if err != nil {
		return key{}, err
	}
	switch c {
	case '\r', '\n':
		return key{name: "enter"}, nil
	case 0x03, 0x04: // Ctrl+C, Ctrl+D
		return key{name: "cancel"}, nil
	case 0x7f, 0x08:
		return key{name: "backspace"}, nil
	case 0x1b:
		return escape(r)
	}
	return key{name: "rune", r: c}, nil
}

// escape разбирает «ESC [ A», «ESC O A», «ESC [ 5 ~» и подобное.
func escape(r *bufio.Reader) (key, error) {
	c, err := r.ReadByte()
	if err != nil {
		return key{}, err
	}
	if c != '[' && c != 'O' {
		return key{name: "other"}, nil
	}
	var seq []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			return key{}, err
		}
		seq = append(seq, c)
		if c >= 0x40 && c <= 0x7e { // последний байт последовательности
			break
		}
		if len(seq) > 8 {
			return key{name: "other"}, nil
		}
	}
	switch string(seq) {
	case "A":
		return key{name: "up"}, nil
	case "B":
		return key{name: "down"}, nil
	case "5~":
		return key{name: "pgup"}, nil
	case "6~":
		return key{name: "pgdn"}, nil
	}
	return key{name: "other"}, nil
}
