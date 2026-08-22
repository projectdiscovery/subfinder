package censys

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rewriteTransport sends every request to the test server while preserving the
// original path/query, so the source's hardcoded api.platform.censys.io URL
// still reaches our handler.
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

	return &subscraping.Session{
		Client:           &http.Client{Transport: &rewriteTransport{target: target}, Timeout: 5 * time.Second},
		MultiRateLimiter: createTestMultiRateLimiter(context.Background()),
		MaxResults:       maxResults,
	}
}

func runCensys(t *testing.T, source *Source, session *subscraping.Session, domain string) (subs []string, errs []error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "censys")

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

// With no per-source limit the source follows the page token until it is empty
// and returns every subdomain, so paid keys are never silently truncated.
func TestCensysSource_FollowsPagesWhenUnlimited(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		// Two pages of one name each, then the page token terminates.
		if n < 2 {
			_, _ = fmt.Fprintf(w, `{"result":{"hits":[{"certificate_v1":{"resource":{"names":["sub%d.example.com"]}}}],"next_page_token":"next-%d"}}`, n, n)
			return
		}
		_, _ = fmt.Fprintf(w, `{"result":{"hits":[{"certificate_v1":{"resource":{"names":["sub%d.example.com"]}}}],"next_page_token":""}}`, n)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"test_pat:test_org"})

	subs, errs := runCensys(t, source, newTestSession(t, server, 0), "example.com")

	assert.Empty(t, errs)
	assert.ElementsMatch(t, []string{"sub1.example.com", "sub2.example.com"}, subs)
	assert.Equal(t, 2, source.Statistics().Requests)
}

// When -max-results (session.MaxResults) is set, pagination must stop as soon
// as the limit is reached so a single domain can't drain an API quota.
func TestCensysSource_MaxResultsCapsPagination(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		// Always return one name plus a non-empty page token so the source would
		// keep paginating (up to maxCensysPages) without the max-results cap.
		_, _ = fmt.Fprintf(w, `{"result":{"hits":[{"certificate_v1":{"resource":{"names":["sub%d.example.com"]}}}],"next_page_token":"next-%d"}}`, n, n)
	}))
	defer server.Close()

	const limit = 3
	source := &Source{}
	source.AddApiKeys([]string{"test_pat:test_org"})

	subs, errs := runCensys(t, source, newTestSession(t, server, limit), "example.com")

	assert.Empty(t, errs, "no errors expected on the happy path")
	assert.Len(t, subs, limit, "should yield exactly max-results subdomains")
	assert.Equal(t, limit, source.Statistics().Requests, "request count must be capped by max-results")
	assert.Equal(t, int32(limit), atomic.LoadInt32(&hits))
}
