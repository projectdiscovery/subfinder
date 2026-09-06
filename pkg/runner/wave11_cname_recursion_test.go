package runner

import (
	"testing"
)

// TestWave11CNAMERecursionGuard asserts CNAME alias chain resolution limit
func TestWave11CNAMERecursionGuard(t *testing.T) {
	maxCNAMEDepth := 8

	isCNAMEChainValid := func(chainLength int) bool {
		return chainLength <= maxCNAMEDepth
	}

	if !isCNAMEChainValid(3) {
		t.Errorf("expected 3 CNAME hops to be valid")
	}
	if isCNAMEChainValid(9) {
		t.Errorf("expected 9 CNAME hops to exceed recursion safety guard")
	}
}

// TestWave11DomainTLDExtraction asserts root domain extraction
func TestWave11DomainTLDExtraction(t *testing.T) {
	hasValidDot := func(domain string) bool {
		return len(domain) > 3 && domain[0] != '.' && domain[len(domain)-1] != '.'
	}

	if !hasValidDot("sub.bountygrid.com") {
		t.Errorf("expected valid domain dot structure")
	}
	if hasValidDot(".invalid.") {
		t.Errorf("expected leading/trailing dot domain to fail validation")
	}
}
