package virustotal

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rewriteTransport sends every request to the test server's host while
// preserving the original path/query, so the source's hardcoded
// www.virustotal.com URL still resolves to our handler.
type rewriteTransport struct {
	target *url.URL
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = r.target.Scheme
	req.URL.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func newTestSession(t *testing.T, server *httptest.Server, maxResults int) *subscraping.Session {
	t.Helper()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)

	mrl, err := ratelimit.NewMultiLimiter(context.Background(), &ratelimit.Options{
		Key:         "virustotal",
		IsUnlimited: false,
		MaxCount:    math.MaxInt32,
		Duration:    time.Millisecond,
	})
	require.NoError(t, err)

	return &subscraping.Session{
		Client:           &http.Client{Transport: &rewriteTransport{target: target}, Timeout: 5 * time.Second},
		MultiRateLimiter: mrl,
		MaxResults:       maxResults,
	}
}

func runSource(t *testing.T, source *Source, session *subscraping.Session, domain string) (subs []string, errs []error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "virustotal")

	for r := range source.Run(ctxWithValue, domain, session) {
		switch r.Type {
		case subscraping.Subdomain:
			subs = append(subs, r.Value)
		case subscraping.Error:
			errs = append(errs, r.Error)
		}
	}
	return
}

func TestVirustotalSource_Metadata(t *testing.T) {
	source := &Source{}
	assert.Equal(t, "virustotal", source.Name())
	assert.True(t, source.IsDefault())
	assert.True(t, source.HasRecursiveSupport())
	assert.True(t, source.NeedsKey())
}

func TestVirustotalSource_NoApiKey(t *testing.T) {
	source := &Source{}

	ctx := context.Background()
	mrl, _ := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
		Key:         "virustotal",
		IsUnlimited: false,
		MaxCount:    math.MaxInt32,
		Duration:    time.Millisecond,
	})
	session := &subscraping.Session{Client: http.DefaultClient, MultiRateLimiter: mrl}
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "virustotal")

	var count int
	for range source.Run(ctxWithValue, "example.com", session) {
		count++
	}
	assert.Equal(t, 0, count, "expected no results without an api key")
	assert.Equal(t, 0, source.Statistics().Requests)
}

// With no per-source limit the source must follow the cursor to the end and
// return every subdomain, i.e. the default behaviour stays unbounded so paid
// keys are never silently truncated.
func TestVirustotalSource_FollowsCursorWhenUnlimited(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		// Three pages of one subdomain each, then the cursor terminates.
		if n < 3 {
			_, _ = fmt.Fprintf(w, `{"data":[{"id":"sub%d.example.com"}],"meta":{"cursor":"next-%d"}}`, n, n)
			return
		}
		_, _ = fmt.Fprintf(w, `{"data":[{"id":"sub%d.example.com"}],"meta":{"cursor":""}}`, n)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})

	subs, errs := runSource(t, source, newTestSession(t, server, 0), "example.com")

	assert.Empty(t, errs)
	assert.ElementsMatch(t, []string{"sub1.example.com", "sub2.example.com", "sub3.example.com"}, subs)
	assert.Equal(t, 3, source.Statistics().Requests)
}

// When -max-results (session.MaxResults) is set, pagination must stop as soon
// as the limit is reached so a single domain can't drain an API quota (#1718).
func TestVirustotalSource_MaxResultsCapsPagination(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		// Always return one subdomain plus a non-empty cursor so the source
		// would loop forever without the max-results cap.
		_, _ = fmt.Fprintf(w, `{"data":[{"id":"sub%d.example.com"}],"meta":{"cursor":"next-%d"}}`, n, n)
	}))
	defer server.Close()

	const limit = 3
	source := &Source{}
	source.AddApiKeys([]string{"test-key"})

	subs, errs := runSource(t, source, newTestSession(t, server, limit), "example.com")

	assert.Empty(t, errs, "no errors expected on the happy path")
	assert.Len(t, subs, limit, "should yield exactly max-results subdomains")
	assert.Equal(t, limit, source.Statistics().Requests, "request count must be capped by max-results")
	assert.Equal(t, int32(limit), atomic.LoadInt32(&hits))
}

// Cursor exhaustion must not waste an extra request.
func TestVirustotalSource_StopsWhenCursorEmpty(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = fmt.Fprint(w, `{"data":[{"id":"a.example.com"}],"meta":{"cursor":"more"}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":[{"id":"b.example.com"}],"meta":{"cursor":""}}`)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})

	subs, errs := runSource(t, source, newTestSession(t, server, 0), "example.com")

	assert.Empty(t, errs)
	assert.ElementsMatch(t, []string{"a.example.com", "b.example.com"}, subs)
	assert.Equal(t, 2, source.Statistics().Requests)
}

// On HTTP 429 (quota exhausted) the source must surface a human-readable error
// mentioning the quota, not a generic "unexpected status code 429" string.
func TestVirustotalSource_RateLimitedReturnsActionableError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})

	_, errs := runSource(t, source, newTestSession(t, server, 0), "example.com")

	require.Len(t, errs, 1, "exactly one error expected on 429")
	assert.Contains(t, errs[0].Error(), "quota exhausted")
	assert.Contains(t, errs[0].Error(), "429")
	assert.Equal(t, 1, source.Statistics().Requests, "must not retry past the first 429")
	assert.Equal(t, 1, source.Statistics().Errors)
}
