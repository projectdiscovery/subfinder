package driftnet

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rewriteTransport sends every request to the test server's host while
// preserving the original path/query, so the source's hardcoded
// api.driftnet.io URL still resolves to our handler.
type rewriteTransport struct {
	target *url.URL
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = r.target.Scheme
	req.URL.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

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

// A key pool mixing blank and valid entries must never let one endpoint
// authenticate while another in the same run doesn't: the key is picked
// once and reused by every endpoint, so a run either skips entirely or
// every endpoint uses that identical, already-verified key (see CodeRabbit
// review on PR #1991). The pool keeps a blank possible on any single draw,
// so every attempt's all-or-nothing invariant is checked regardless of
// outcome, and the loop retries, up to a bound, until one attempt actually
// draws the valid key - keeping the "at least one authenticated run"
// assertion deterministic rather than resting on chance across a fixed
// iteration count.
func TestDriftnetSource_MixedBlankAndValidKeysNeverPartiallyAuthenticates(t *testing.T) {
	ctx := context.Background()
	mrl, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
		Key: "driftnet", IsUnlimited: false, MaxCount: math.MaxInt32, Duration: time.Millisecond,
	})
	require.NoError(t, err)
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "driftnet")

	// One in five draws (1 valid key in a 5-entry pool) authenticates, so
	// 200 attempts leaves negligible odds of seeing fewer than
	// minAuthenticatedRuns authenticated runs; stopping at the first one
	// would leave this checking only a single draw, no more rigorous than
	// a one-shot assertion.
	const maxAttempts = 200
	const minAuthenticatedRuns = 5
	var authenticatedRuns int
	for i := 0; i < maxAttempts && authenticatedRuns < minAuthenticatedRuns; i++ {
		var mu sync.Mutex
		var authHeaders []string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			authHeaders = append(authHeaders, r.Header.Get("authorization"))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}))

		target, err := url.Parse(server.URL)
		require.NoError(t, err)

		source := &Source{}
		// A pool mixing blanks and one valid entry: the single draw can
		// land on either, but it must never differ between endpoints.
		source.AddApiKeys([]string{"", "", "", "valid-key", ""})
		session := &subscraping.Session{Client: &http.Client{Transport: &rewriteTransport{target: target}}, MultiRateLimiter: mrl}

		for range source.Run(ctxWithValue, "example.com", session) {
		}
		server.Close()

		mu.Lock()
		switch len(authHeaders) {
		case 0:
			// The single draw landed on a blank key: the whole run skips,
			// never sending a partially-authenticated batch. Retry.
		case len(endpoints):
			for _, h := range authHeaders {
				assert.Equal(t, "Bearer valid-key", h, "every endpoint in one run must use the same key")
			}
			authenticatedRuns++
		default:
			t.Errorf("attempt %d: got %d requests, want 0 or %d", i, len(authHeaders), len(endpoints))
		}
		mu.Unlock()
	}
	require.GreaterOrEqual(t, authenticatedRuns, minAuthenticatedRuns,
		"too few attempts drew the valid key within %d tries", maxAttempts)
}
