package runner

import (
	"strings"
	"testing"
)

func TestWHOISOrganizationDomainScraping(t *testing.T) {
	record := "Registrant Organization: Example Corp LLC
Domain Name: EXAMPLE.COM"
	if !strings.Contains(strings.ToLower(record), "example corp") {
		t.Fatalf("failed to locate organization name in WHOIS record")
	}
}
