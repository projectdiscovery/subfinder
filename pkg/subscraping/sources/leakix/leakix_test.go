package leakix

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rewriteTransport sends every request to the test server's host while
// preserving the original path/query, so the source's hardcoded
// leakix.net URL still resolves to our handler.
type rewriteTransport struct {
	target *url.URL
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = r.target.Scheme
	req.URL.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

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

// A key pool mixing blank and valid entries must select the valid key, not
// skip just because PickRandom's draw could land on a blank entry (see
// CodeRabbit review on PR #1991: PickRandom now excludes blanks before
// picking).
func TestLeakixSource_MixedBlankAndValidKeysSelectsValidKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "valid-key", r.Header.Get("api-key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	target, err := url.Parse(server.URL)
	require.NoError(t, err)

	source := &Source{}
	source.AddApiKeys([]string{"", "", "", "valid-key", ""})

	ctx := context.Background()
	mrl, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
		Key: "leakix", IsUnlimited: false, MaxCount: math.MaxInt32, Duration: time.Millisecond,
	})
	require.NoError(t, err)
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "leakix")
	session := &subscraping.Session{Client: &http.Client{Transport: &rewriteTransport{target: target}}, MultiRateLimiter: mrl}

	for range source.Run(ctxWithValue, "example.com", session) {
	}

	stats := source.Statistics()
	assert.Equal(t, 1, stats.Requests, "a usable key is configured, so the request must be sent")
	assert.False(t, stats.Skipped, "must not skip when a usable key is present in the pool")
}
