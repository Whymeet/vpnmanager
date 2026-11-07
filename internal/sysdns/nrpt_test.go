package sysdns

import (
	"fmt"
	"slices"
	"testing"
)

func TestNRPTChunks(t *testing.T) {
	got := nrptChunks([]string{"Notion.so", "notion.so", "figma.com", ".slack.com"})
	if len(got) != 1 || !slices.Equal(got[0], []string{".figma.com", ".notion.so", ".slack.com"}) {
		t.Fatalf("%v", got)
	}
	var many []string
	for i := range 120 {
		many = append(many, fmt.Sprintf("d%03d.com", i))
	}
	chunks := nrptChunks(many)
	if len(chunks) != 3 || len(chunks[0]) != nrptPerRule || len(chunks[2]) != 20 {
		t.Fatalf("120 доменов разложены как %d правил: %d, …, %d", len(chunks), len(chunks[0]), len(chunks[len(chunks)-1]))
	}
	if nrptChunks(nil) != nil {
		t.Fatal("без доменов — без правил")
	}
}

func TestCoveredByForeignRule(t *testing.T) {
	foreign := []string{".corp.example", "intra.local", " .Notion.so "}
	for d, want := range map[string]bool{
		"notion.so":          true,
		"www.notion.so":      true,
		"app.corp.example":   true,
		"intra.local":        true,
		"figma.com":          false,
		"notnotion.so":       false,
		"corp.example.other": false,
	} {
		if got := coveredBy(foreign, d); got != want {
			t.Errorf("%s: %v, ждали %v", d, got, want)
		}
	}
}
