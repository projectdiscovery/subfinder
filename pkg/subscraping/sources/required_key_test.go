package sources_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

func TestRequiredKeySourcesSkipWithoutKey(t *testing.T) {
	for _, source := range concurrencySources() {
		if source.KeyRequirement() != subscraping.RequiredKey {
			continue
		}
		t.Run(source.Name(), func(t *testing.T) {
			var requests atomic.Int32
			transport := transportFunc(func(req *http.Request) (*http.Response, error) {
				requests.Add(1)
				return failingTransport(req)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			outcome := awaitRun(t, ctx, startRun(t, ctx, source, "example.com", transport, 0))
			if got := requests.Load(); got != 0 {
				t.Errorf("sent %d requests without an API key", got)
			}
			checkOutcome(t, outcome, runOutcome{stats: subscraping.Statistics{Skipped: true}})
		})
	}
}
