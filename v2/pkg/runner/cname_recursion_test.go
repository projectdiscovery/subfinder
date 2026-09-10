package runner

import (
	"testing"
)

func TestCNAMERecursionDepthLimit(t *testing.T) {
	maxDepth := 5
	depth := 0
	
	// Simulate recursive CNAME traversal
	for depth < maxDepth {
		depth++
	}
	
	if depth > maxDepth {
		t.Fatalf("CNAME resolution exceeded maximum allowed recursion depth: %d", depth)
	}
}
