package sysdns

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func fake(active, link bool, fail func(call string) error) (Resolved, *[]string) {
	var calls []string
	r := Resolved{
		Addr:    netip.MustParseAddrPort("127.0.0.1:53535"),
		Active:  func() bool { return active },
		Enabled: func() bool { return false },
		Link:    func(name string) bool { return link && name == Iface },
		Sleep:   func(time.Duration) {},
		Run: func(name string, args ...string) error {
			call := name + " " + strings.Join(args, " ")
			calls = append(calls, call)
			if fail != nil {
				return fail(call)
			}
			return nil
		},
	}
	return r, &calls
}

func TestSetRoutesOnlyProtectedDomains(t *testing.T) {
	r, calls := fake(true, false, nil)
	if _, err := r.Set([]string{"openai.com", "anthropic.com"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip link add appguard0 type dummy",
		"ip addr add 169.254.53.53/32 dev appguard0 scope global",
		"ip link set appguard0 up",
		"resolvectl dns appguard0 127.0.0.1:53535",
		"resolvectl domain appguard0 ~anthropic.com ~openai.com",
		"resolvectl default-route appguard0 false",
		"resolvectl flush-caches",
	}
	if !slices.Equal(*calls, want) {
		t.Errorf("%q", *calls)
	}
}

// resolved принимает 256 доменов на интерфейс и на 257-м отказывает всем сразу.
func TestSetSpreadsLargeListOverLinks(t *testing.T) {
	r, calls := fake(true, false, nil)
	domains := make([]string, 300)
	for i := range domains {
		domains[i] = fmt.Sprintf("d%03d.example", i)
	}
	if _, err := r.Set(domains); err != nil {
		t.Fatal(err)
	}
	sizes := map[string]int{}
	for _, c := range *calls {
		if f := strings.Fields(c); f[1] == "domain" {
			sizes[f[2]] = len(f) - 3
		}
	}
	if sizes["appguard0"] != 256 || sizes["appguard1"] != 44 || len(sizes) != 2 {
		t.Errorf("%v", sizes)
	}
}

func TestSetDropsLinksNoLongerNeeded(t *testing.T) {
	r, calls := fake(true, true, nil)
	r.Link = func(name string) bool { return name == "appguard0" || name == "appguard1" }
	if _, err := r.Set([]string{"openai.com"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(*calls, "ip link del appguard1") || slices.Contains(*calls, "ip link del appguard0") {
		t.Errorf("%q", *calls)
	}
}

func TestSetWaitsForResolvedToSeeTheLink(t *testing.T) {
	left := 3
	r, calls := fake(true, true, func(call string) error {
		if strings.Contains(call, "dns appguard0") && left > 0 {
			left--
			return errors.New("Link appguard0 not known")
		}
		return nil
	})
	if _, err := r.Set([]string{"openai.com"}); err != nil {
		t.Fatal(err)
	}
	if n := len(*calls); n != 7 {
		t.Errorf("%d вызовов: %q", n, *calls)
	}
}

// При загрузке служба стартует раньше resolved: молчать нельзя, домены не применились бы.
func TestSetAsksToRetryWhileResolvedStarts(t *testing.T) {
	r, calls := fake(false, false, nil)
	r.Enabled = func() bool { return true }
	if _, err := r.Set([]string{"openai.com"}); err == nil {
		t.Error("ошибки нет: повторять будет некому")
	}
	if len(*calls) != 0 {
		t.Errorf("%q", *calls)
	}
}

func TestSetWithoutResolvedChangesNothing(t *testing.T) {
	r, calls := fake(false, false, nil)
	if _, err := r.Set([]string{"openai.com"}); err != nil || len(*calls) != 0 {
		t.Errorf("%v %q", err, *calls)
	}
}

func TestNoDomainsLeaveNoLink(t *testing.T) {
	r, calls := fake(true, true, nil)
	if _, err := r.Set(nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*calls, []string{"ip link del appguard0"}) {
		t.Errorf("%q", *calls)
	}
	r, calls = fake(true, false, nil)
	if err := r.Clear(); err != nil || len(*calls) != 0 {
		t.Errorf("%v %q", err, *calls)
	}
}
