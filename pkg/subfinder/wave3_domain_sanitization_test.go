package subfinder

import (
	"strings"
	"testing"
)

func TestWave3DomainSanitization(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"*.EXAMPLE.COM", "example.com"},
		{"  sub.target.org  ", "sub.target.org"},
		{"api.v1.domain.io.", "api.v1.domain.io"},
		{"*.*.nested.target.com", "nested.target.com"},
	}

	clean := func(domain string) string {
		d := strings.TrimSpace(strings.ToLower(domain))
		d = strings.TrimLeft(d, "*.")
		return strings.TrimSuffix(d, ".")
	}

	for _, tc := range testCases {
		res := clean(tc.input)
		if res != tc.expected {
			t.Errorf("clean(%q) = %q; want %q", tc.input, res, tc.expected)
		}
	}
}

func TestWave3WildcardDeduplication(t *testing.T) {
	domains := []string{"a.com", "b.com", "a.com", "c.com", "b.com"}
	seen := make(map[string]bool)
	var unique []string

	for _, d := range domains {
		if !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}

	if len(unique) != 3 {
		t.Errorf("expected 3 unique domains, got %d", len(unique))
	}
}
