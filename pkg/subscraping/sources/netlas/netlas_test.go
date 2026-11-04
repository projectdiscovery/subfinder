package netlas

import (
	"context"
	"net/http"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
)

// Without a configured API key the source must not send the domains_count
// request (which the upstream API rejects, and whose failure previously
// still let a second unauthenticated download request through); it should
// skip both requests and report Statistics.Skipped instead.
func TestNetlasSource_NoApiKeySkipsRequest(t *testing.T) {
	source := &Source{}

	ctx := context.Background()
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "netlas")
	session := &subscraping.Session{Client: http.DefaultClient}

	var count int
	for range source.Run(ctxWithValue, "example.com", session) {
		count++
	}

	assert.Equal(t, 0, count, "expected no results without an api key")
	stats := source.Statistics()
	assert.Equal(t, 0, stats.Requests, "must not send any request without a key")
	assert.True(t, stats.Skipped, "Statistics.Skipped must be set when the key is missing")
}
