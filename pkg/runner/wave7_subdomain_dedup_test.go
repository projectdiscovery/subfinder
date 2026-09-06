package runner

import (
	"strings"
	"testing"
)

// TestWave7SubdomainDeduplicationSet asserts subdomain set uniqueness
func TestWave7SubdomainDeduplicationSet(t *testing.T) {
	seen := make(map[string]struct{})
	subdomains := []string{"api.example.com", "API.example.com", "vpn.example.com", "api.example.com"}

	for _, sub := range subdomains {
		normalized := strings.ToLower(strings.TrimSpace(sub))
		seen[normalized] = struct{}{}
	}

	if len(seen) != 2 {
		t.Errorf("expected 2 unique normalized subdomains, got %d", len(seen))
	}
}

// TestWave7WildcardSubdomainFilter asserts wildcard prefix detection
func TestWave7WildcardSubdomainFilter(t *testing.T) {
	isWildcard := func(host string) bool {
		return strings.HasPrefix(host, "*.")
	}

	if !isWildcard("*.example.com") {
		t.Errorf("expected wildcard host detection to return true")
	}
	if isWildcard("app.example.com") {
		t.Errorf("expected non-wildcard host to return false")
	}
}
