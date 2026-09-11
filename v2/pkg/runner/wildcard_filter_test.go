package runner

import (
	"strings"
	"testing"
)

func TestSubdomainWildcardPrefixSanitization(t *testing.T) {
	rawHost := "*.api.example.com"
	cleanHost := strings.TrimPrefix(rawHost, "*.")
	
	if cleanHost != "api.example.com" {
		t.Fatalf("failed to strip wildcard asterisk prefix: %s", cleanHost)
	}
}
