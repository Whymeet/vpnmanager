// Package sysdns направляет имена защищённых доменов на резолвер службы. На
// macOS это файл /etc/resolver/<домен>: система шлёт туда запросы домена и
// всех его поддоменов, даже если VPN выставил свои DNS.
package sysdns

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// Dir — каталог доменных резолверов macOS.
const Dir = "/etc/resolver"

// marker — первая строка наших файлов: по ней удаление узнаёт своё и не
// трогает чужое.
const marker = "# appguard"

// Resolvers — доменные резолверы appguard.
type Resolvers struct {
	Dir  string         // каталог файлов; в тестах — временный
	Addr netip.AddrPort // где слушает резолвер службы
	// Flush сбрасывает кэш DNS системы: ответы, полученные до защиты, не
	// должны жить мимо таблиц. nil — сбрасывать нечем (тесты).
	Flush func() error
}

// System — резолверы на живой системе.
func System(addr netip.AddrPort) Resolvers {
	return Resolvers{Dir: Dir, Addr: addr, Flush: flushCache}
}

// Set направляет на службу ровно эти домены: недостающие файлы пишет, свои
// лишние удаляет. Чужой файл с тем же именем не трогает и возвращает такие
// домены в skipped.
func (r Resolvers) Set(domains []string) (skipped []string, err error) {
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		return nil, err
	}
	want := map[string]bool{}
	changed := false
	for _, d := range domains {
		want[d] = true
		path := filepath.Join(r.Dir, d)
		cur, err := os.ReadFile(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return skipped, err
		case !ours(cur):
			skipped = append(skipped, d)
			continue
		case bytes.Equal(cur, r.content()):
			continue
		}
		if err := os.WriteFile(path, r.content(), 0o644); err != nil {
			return skipped, err
		}
		changed = true
	}
	mine, err := r.mine()
	if err != nil {
		return skipped, err
	}
	for _, d := range mine {
		if !want[d] {
			if err := os.Remove(filepath.Join(r.Dir, d)); err != nil {
				return skipped, err
			}
			changed = true
		}
	}
	if changed {
		return skipped, r.flush()
	}
	return skipped, nil
}

// Clear удаляет все наши файлы. Каталог остаётся: он системный.
func (r Resolvers) Clear() error {
	_, err := r.Set(nil)
	return err
}

func (r Resolvers) content() []byte {
	return fmt.Appendf(nil, "%s: имена этого домена разрешает служба appguard, файл снимет «appguard uninstall»\nnameserver %s\nport %d\n",
		marker, r.Addr.Addr(), r.Addr.Port())
}

// mine — домены, файлы которых написали мы.
func (r Resolvers) mine() ([]string, error) {
	entries, err := os.ReadDir(r.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			if data, err := os.ReadFile(filepath.Join(r.Dir, e.Name())); err == nil && ours(data) {
				out = append(out, e.Name())
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

func ours(data []byte) bool {
	line, _, _ := bufio.NewReader(bytes.NewReader(data)).ReadLine()
	return strings.HasPrefix(string(line), marker)
}

func (r Resolvers) flush() error {
	if r.Flush == nil {
		return nil
	}
	return r.Flush()
}

// flushCache сбрасывает кэш DNS macOS.
func flushCache() error {
	if out, err := exec.Command("/usr/bin/dscacheutil", "-flushcache").CombinedOutput(); err != nil {
		return fmt.Errorf("dscacheutil: %w: %s", err, bytes.TrimSpace(out))
	}
	if out, err := exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").CombinedOutput(); err != nil {
		return fmt.Errorf("mDNSResponder: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
