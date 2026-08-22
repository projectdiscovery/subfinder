package certspotter

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

// rewriteTransport sends every request to the test server while preserving the
// original path/query, so the source's hardcoded api.certspotter.com URL still
// reaches our handler.
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
		Key:         "certspotter",
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
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "certspotter")

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

func TestCertspotterSource_Metadata(t *testing.T) {
	source := &Source{}
	assert.Equal(t, "certspotter", source.Name())
	assert.True(t, source.IsDefault())
	assert.True(t, source.HasRecursiveSupport())
	assert.True(t, source.NeedsKey())
}

func TestCertspotterSource_NoApiKey(t *testing.T) {
	source := &Source{}

	ctx := context.Background()
	mrl, _ := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
		Key:         "certspotter",
		IsUnlimited: false,
		MaxCount:    math.MaxInt32,
		Duration:    time.Millisecond,
	})
	session := &subscraping.Session{Client: http.DefaultClient, MultiRateLimiter: mrl}
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "certspotter")

	var count int
	for range source.Run(ctxWithValue, "example.com", session) {
		count++
	}
	assert.Equal(t, 0, count, "expected no results without an api key")
	assert.True(t, source.Statistics().Skipped)
}

// With no per-source limit the source walks the "after" cursor to the end and
// returns every subdomain, i.e. the default behaviour stays unbounded.
func TestCertspotterSource_FollowsCursorWhenUnlimited(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		// Two issuances, then an empty page terminates pagination.
		if n < 3 {
			_, _ = fmt.Fprintf(w, `[{"id":"%d","dns_names":["sub%d.example.com"]}]`, n, n)
			return
		}
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})

	subs, errs := runSource(t, source, newTestSession(t, server, 0), "example.com")

	assert.Empty(t, errs)
	assert.ElementsMatch(t, []string{"sub1.example.com", "sub2.example.com"}, subs)
}

// When -max-results (session.MaxResults) is set, pagination must stop as soon
// as the limit is reached so a single domain can't drain an API quota.
func TestCertspotterSource_MaxResultsCapsPagination(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		// Always return one issuance with a fresh id so the source would paginate
		// forever via the "after" cursor without the max-results cap.
		_, _ = fmt.Fprintf(w, `[{"id":"%d","dns_names":["sub%d.example.com"]}]`, n, n)
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
