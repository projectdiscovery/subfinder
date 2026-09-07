package resolve

import "testing"

func ResolveCNAMEChain(target string, lookup map[string]string, maxDepth int) ([]string, bool) {
	visited := make(map[string]bool)
	chain := []string{target}
	visited[target] = true
	curr := target

	for i := 0; i < maxDepth; i++ {
		next, exists := lookup[curr]
		if !exists {
			return chain, true // Normal termination
		}
		if visited[next] {
			return chain, false // Cycle loop detected
		}
		visited[next] = true
		chain = append(chain, next)
		curr = next
	}
	return chain, false // Exceeded max depth
}

func TestWave16CNAMERecursionGuard(t *testing.T) {
	lookup := map[string]string{
		"a.example.com": "b.example.com",
		"b.example.com": "c.example.com",
		"c.example.com": "d.example.com",
	}

	chain, ok := ResolveCNAMEChain("a.example.com", lookup, 5)
	if !ok || len(chain) != 4 {
		t.Fatalf("expected valid resolution of depth 4, got len %d (ok=%v)", len(chain), ok)
	}

	// Test loop detection
	loopLookup := map[string]string{
		"a.example.com": "b.example.com",
		"b.example.com": "a.example.com",
	}
	_, loopOk := ResolveCNAMEChain("a.example.com", loopLookup, 5)
	if loopOk {
		t.Fatalf("expected cycle detection failure")
	}
}
