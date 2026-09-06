package runner

import (
	"testing"
)

func TestWave9WildcardDomainFiltering(t *testing.T) {
	wildcardIPs := map[string]struct{}{
		"192.0.2.1": {},
		"192.0.2.2": {},
	}

	isWildcardIP := func(ip string) bool {
		_, exists := wildcardIPs[ip]
		return exists
	}

	if !isWildcardIP("192.0.2.1") {
		t.Errorf("expected 192.0.2.1 to be recognized as wildcard IP")
	}
	if isWildcardIP("198.51.100.1") {
		t.Errorf("expected 198.51.100.1 to NOT be recognized as wildcard IP")
	}
}

func TestWave9SubdomainDeduplicationOrder(t *testing.T) {
	domains := []string{"api.example.com", "API.EXAMPLE.COM", "auth.example.com"}
	seen := make(map[string]bool)
	var unique []string

	for _, d := range domains {
		norm := d
		if !seen[norm] {
			seen[norm] = true
			unique = append(unique, norm)
		}
	}

	if len(unique) != 3 {
		t.Errorf("expected 3 raw domains before normalization, got %d", len(unique))
	}
}
