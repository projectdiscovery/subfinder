package digicert

import (
	"context"
	"strings"
	"testing"

	"github.com/subfinder/subfinder/pkg/subscraping"
)

func TestDigicert(t *testing.T) {
	agent, _ := subscraping.New("", 30)
	session, err := agent.NewSession("freelancer.com", subscraping.Keys{})
	if err != nil {
		t.Fatalf("Invalid subdomain found: %s\n", err)
	}

	source := Source{}
	for resp := range source.Run(context.Background(), "freelancer.com", session) {
		if resp.Type == subscraping.Error {
			t.Fatalf("Source %s errored out: %s\n", source.Name(), resp.Error)
		}
		if !strings.HasSuffix(resp.Value, "freelancer.com") {
			t.Fatalf("Invalid, expected for %s got %s\n", "freelancer.com", resp.Value)
		}
	}
}
