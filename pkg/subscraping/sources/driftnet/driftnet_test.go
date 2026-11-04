package driftnet

import (
	"context"
	"net/http"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
)

// Without a configured API key none of the four driftnet endpoints must send
// an unauthenticated request (each previously got a 401 from the upstream
// API, surfacing as four separate warnings for one missing key); the source
// should skip entirely and report Statistics.Skipped instead.
func TestDriftnetSource_NoApiKeySkipsRequest(t *testing.T) {
	source := &Source{}

	ctx := context.Background()
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "driftnet")
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
