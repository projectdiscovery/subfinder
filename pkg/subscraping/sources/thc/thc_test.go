package thc

import (
	"context"
	"encoding/json"
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
// preserving the original path, so the source's hardcoded thc URL still
// resolves to our handler.
type rewriteTransport struct {
	target *url.URL
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = r.target.Scheme
	req.URL.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func runSource(t *testing.T, server *httptest.Server, maxResults int) (source *Source, subs []string, errs []error) {
	t.Helper()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)

	mrl, err := ratelimit.NewMultiLimiter(context.Background(), &ratelimit.Options{
		Key:         "thc",
		IsUnlimited: false,
		MaxCount:    math.MaxInt32,
		Duration:    time.Millisecond,
	})
	require.NoError(t, err)
	session := &subscraping.Session{
		Client:           &http.Client{Transport: &rewriteTransport{target: target}, Timeout: 5 * time.Second},
		MultiRateLimiter: mrl,
		MaxResults:       maxResults,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, "thc")

	source = &Source{}
	for r := range source.Run(ctx, "example.com", session) {
		switch r.Type {
		case subscraping.Subdomain:
			subs = append(subs, r.Value)
		case subscraping.Error:
			errs = append(errs, r.Error)
		}
	}
	return source, subs, errs
}

// newPagedServer serves three pages of two names each, chained by page_state.
func newPagedServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req requestBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		page := int(atomic.AddInt32(&hits, 1))
		next := ""
		if page < 3 {
			next = fmt.Sprintf("state-%d", page)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"domains":[{"domain":"a%d.example.com"},{"domain":"b%d.example.com"}],"next_page_state":%q}`, page, page, next)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func TestTHCSource_FollowsPagesWhenUnlimited(t *testing.T) {
	server, hits := newPagedServer(t)

	source, subs, errs := runSource(t, server, 0)

	assert.Empty(t, errs)
	assert.Len(t, subs, 6)
	assert.Equal(t, 3, source.Statistics().Requests)
	assert.Equal(t, int32(3), atomic.LoadInt32(hits))
}

// With -max-results set, pagination must stop once the limit is reached
// instead of reading every page.
func TestTHCSource_HonorsMaxResults(t *testing.T) {
	server, hits := newPagedServer(t)

	source, subs, errs := runSource(t, server, 3)

	assert.Empty(t, errs)
	assert.Equal(t, []string{"a1.example.com", "b1.example.com", "a2.example.com"}, subs)
	assert.Equal(t, 2, source.Statistics().Requests)
	assert.Equal(t, int32(2), atomic.LoadInt32(hits))
}
