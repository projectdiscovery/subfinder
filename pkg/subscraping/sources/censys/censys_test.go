package censys

import (
	"strings"
	"testing"
)

func TestAddApiKeysRequiresOrgId(t *testing.T) {
	source := Source{}
	source.AddApiKeys([]string{" token-one : org-1 ", "token-two:org-2", "missing", "no-org:", " :no-token"})

	if len(source.apiKeys) != 2 {
		t.Fatalf("expected 2 valid entries, got %d", len(source.apiKeys))
	}

	if source.apiKeys[0].token != "token-one" || source.apiKeys[0].orgID != "org-1" {
		t.Fatalf("expected first entry to be token-one/org-1, got token=%q org=%q", source.apiKeys[0].token, source.apiKeys[0].orgID)
	}

	if source.apiKeys[1].token != "token-two" || source.apiKeys[1].orgID != "org-2" {
		t.Fatalf("expected second entry to be token-two/org-2, got token=%q org=%q", source.apiKeys[1].token, source.apiKeys[1].orgID)
	}
}

func TestSanitizeCandidate(t *testing.T) {
	domain := "example.com"
	testCases := []struct {
		name     string
		value    string
		expected string
		valid    bool
	}{
		{"exact match", "example.com", "example.com", true},
		{"subdomain", "api.example.com", "api.example.com", true},
		{"uppercase", "WWW.EXAMPLE.COM", "www.example.com", true},
		{"wildcard", "*.mail.example.com", "mail.example.com", true},
		{"trailing dot", "test.example.com.", "test.example.com", true},
		{"non-matching", "otherdomain.com", "", false},
		{"empty", "", "", false},
	}

	domainLower := strings.ToLower(domain)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sanitizeCandidate(tc.value, domainLower)
			if ok != tc.valid {
				t.Fatalf("expected valid=%v, got %v", tc.valid, ok)
			}
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}
