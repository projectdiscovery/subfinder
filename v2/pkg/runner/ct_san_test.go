package runner

import (
	"strings"
	"testing"
)

func TestCertificateTransparencySubjectAltNameParsing(t *testing.T) {
	sanEntry := "DNS:auth.internal.example.com, DNS:api.example.com"
	names := strings.Split(sanEntry, ", ")
	
	if len(names) != 2 {
		t.Fatalf("expected 2 SAN entries, got %d", len(names))
	}
	if !strings.HasPrefix(names[0], "DNS:") {
		t.Fatalf("malformed SAN DNS prefix")
	}
}
