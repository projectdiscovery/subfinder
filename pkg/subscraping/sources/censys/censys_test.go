package censys

import (
	"strings"
	"testing"
)

func TestAddApiKeysStoresPersonalAccessTokens(t *testing.T) {
	source := Source{}
	source.AddApiKeys([]string{"token-one", " token-two : org-id ", "legacy:id"})

	if len(source.apiKeys) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(source.apiKeys))
	}

	if source.apiKeys[0].token != "token-one" || source.apiKeys[0].orgID != "" {
		t.Fatalf("expected first token to be 'token-one' without org, got token=%q org=%q", source.apiKeys[0].token, source.apiKeys[0].orgID)
	}

	if source.apiKeys[1].token != "token-two" || source.apiKeys[1].orgID != "org-id" {
		t.Fatalf("expected trimmed token/org pairing, got token=%q org=%q", source.apiKeys[1].token, source.apiKeys[1].orgID)
	}

	if source.apiKeys[2].token != "legacy" || source.apiKeys[2].orgID != "id" {
		t.Fatalf("expected legacy token to split as PAT+org, got token=%q org=%q", source.apiKeys[2].token, source.apiKeys[2].orgID)
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
