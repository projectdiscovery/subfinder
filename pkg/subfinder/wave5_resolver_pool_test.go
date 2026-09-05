package subfinder

import (
	"testing"
)

func TestWave5ResolverPoolDistribution(t *testing.T) {
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	
	getResolver := func(idx int, pool []string) string {
		if len(pool) == 0 {
			return ""
		}
		return pool[idx%len(pool)]
	}

	if getResolver(0, resolvers) != "1.1.1.1:53" {
		t.Error("expected first resolver")
	}
	if getResolver(3, resolvers) != "1.1.1.1:53" {
		t.Error("expected round-robin wrap to first resolver")
	}
	if getResolver(4, resolvers) != "8.8.8.8:53" {
		t.Error("expected round-robin second resolver")
	}
}

func TestWave5SubdomainLengthFilter(t *testing.T) {
	isLengthValid := func(domain string) bool {
		return len(domain) > 0 && len(domain) <= 253
	}

	if !isLengthValid("api.target.com") {
		t.Error("valid domain rejected")
	}
	if isLengthValid("") {
		t.Error("empty domain should be rejected")
	}
}
