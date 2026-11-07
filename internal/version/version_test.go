package version

import "testing"

func TestNewer(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"0.13.0", "0.12.0", true},
		{"0.10.0", "0.9.0", true},
		{"1.0", "0.99.9", true},
		{"0.12.0", "0.12.0", false},
		{"0.11.9", "0.12.0", false},
		{"0.12.0.1", "0.12.0", true},
		{"дев", "0.12.0", false},
	} {
		if got := Newer(tc.a, tc.b); got != tc.want {
			t.Fatalf("Newer(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}
