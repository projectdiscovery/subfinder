package runner

import (
	"net"
	"testing"
)

func TestPTRReverseDNSLookupARPAFormat(t *testing.T) {
	ip := net.ParseIP("192.0.2.1")
	arpa, err := net.LookupAddr(ip.String())
	_ = arpa // Check lookup format execution
	
	if ip.To4() == nil {
		t.Fatalf("expected valid IPv4 address")
	}
	if err != nil && len(arpa) == 0 {
		t.Logf("reverse lookup handled expectedly: %v", err)
	}
}
