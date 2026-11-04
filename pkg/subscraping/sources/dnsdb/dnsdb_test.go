package dnsdb

import (
	"context"
	"net/http"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
)

// The source already skips the request when no key is configured; it must
// also report Statistics.Skipped instead of leaving the run looking like a
// clean zero-request pass (see issue: sources that require a key run
// without one).
func TestDnsdbSource_NoApiKeySetsSkipped(t *testing.T) {
	source := &Source{}

	ctx := context.Background()
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "dnsdb")
	session := &subscraping.Session{Client: http.DefaultClient}

	var count int
	for range source.Run(ctxWithValue, "example.com", session) {
		count++
	}

	assert.Equal(t, 0, count, "expected no results without an api key")
	stats := source.Statistics()
	assert.Equal(t, 0, stats.Requests)
	assert.True(t, stats.Skipped, "Statistics.Skipped must be set when the key is missing")
}
