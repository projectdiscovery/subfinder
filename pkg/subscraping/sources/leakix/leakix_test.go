package leakix

import (
	"context"
	"net/http"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
)

// Without a configured API key the source must not send the unauthenticated
// request that the upstream API rejects with 401; it should skip and report
// Statistics.Skipped instead (see issue: sources that require a key run
// without one).
func TestLeakixSource_NoApiKeySkipsRequest(t *testing.T) {
	source := &Source{}

	ctx := context.Background()
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "leakix")
	session := &subscraping.Session{Client: http.DefaultClient}

	var count int
	for range source.Run(ctxWithValue, "example.com", session) {
		count++
	}

	assert.Equal(t, 0, count, "expected no results without an api key")
	stats := source.Statistics()
	assert.Equal(t, 0, stats.Requests, "must not send a request without a key")
	assert.True(t, stats.Skipped, "Statistics.Skipped must be set when the key is missing")
}
