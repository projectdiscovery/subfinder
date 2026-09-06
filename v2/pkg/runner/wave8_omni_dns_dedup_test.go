package runner

import (
	"strings"
	"testing"
)

func TestWave8OmniSubdomainDeduplication(t *testing.T) {
	deduplicateSubdomains := func(domains []string) []string {
		seen := make(map[string]bool)
		var unique []string
		for _, d := range domains {
			cleaned := strings.ToLower(strings.TrimSpace(d))
			if cleaned != "" && !seen[cleaned] {
				seen[cleaned] = true
				unique = append(unique, cleaned)
			}
		}
		return unique
	}

	input := []string{"api.example.com", "API.EXAMPLE.COM", "  api.example.com  ", "auth.example.com", ""}
	result := deduplicateSubdomains(input)

	if len(result) != 2 {
		t.Fatalf("expected 2 unique subdomains, got %d", len(result))
	}
	if result[0] != "api.example.com" || result[1] != "auth.example.com" {
		t.Errorf("unexpected deduplication result: %v", result)
	}
}

func TestWave8OmniDNSWildcardFilter(t *testing.T) {
	isWildcardResponse := func(ip string, knownWildcardIPs []string) bool {
		for _, w := range knownWildcardIPs {
			if ip == w {
				return true
			}
		}
		return false
	}

	wildcards := []string{"192.168.1.1", "10.0.0.1"}
	if !isWildcardResponse("192.168.1.1", wildcards) {
		t.Error("expected true for known wildcard IP")
	}
	if isWildcardResponse("8.8.8.8", wildcards) {
		t.Error("expected false for legitimate target IP")
	}
}
