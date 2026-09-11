package runner

import (
	"testing"
)

func TestAutonomousSystemNumberAggregation(t *testing.T) {
	asnList := []string{"AS15169", "AS13335", "AS15169"}
	uniqueASNs := make(map[string]bool)
	
	for _, asn := range asnList {
		uniqueASNs[asn] = true
	}
	
	if len(uniqueASNs) != 2 {
		t.Fatalf("expected 2 unique ASNs, got %d", len(uniqueASNs))
	}
}
