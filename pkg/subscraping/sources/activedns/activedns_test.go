package activedns

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

type rewriteTransport struct {
	target *url.URL
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = r.target.Scheme
	req.URL.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func newTestSession(t *testing.T, server *httptest.Server, domain string, maxResults int) *subscraping.Session {
	t.Helper()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)

	extractor, err := subscraping.NewSubdomainExtractor(domain)
	require.NoError(t, err)

	mrl, err := ratelimit.NewMultiLimiter(context.Background(), &ratelimit.Options{
		Key:         "activedns",
		IsUnlimited: false,
		MaxCount:    math.MaxInt32,
		Duration:    time.Millisecond,
	})
	require.NoError(t, err)

	return &subscraping.Session{
		Client:           &http.Client{Transport: &rewriteTransport{target: target}, Timeout: 5 * time.Second},
		MultiRateLimiter: mrl,
		Extractor:        extractor,
		MaxResults:       maxResults,
	}
}

func runSource(t *testing.T, source *Source, session *subscraping.Session, domain string) (subs []string, errs []error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, "activedns")

	for r := range source.Run(ctx, domain, session) {
		switch r.Type {
		case subscraping.Subdomain:
			subs = append(subs, r.Value)
		case subscraping.Error:
			errs = append(errs, r.Error)
		}
	}
	return
}

func TestActiveDNSSource_Metadata(t *testing.T) {
	source := &Source{}
	assert.Equal(t, "activedns", source.Name())
	assert.True(t, source.IsDefault())
	assert.True(t, source.HasRecursiveSupport())
	assert.True(t, source.NeedsKey())
	assert.Equal(t, subscraping.RequiredKey, source.KeyRequirement())
}

func TestActiveDNSSource_SkipsWithoutKey(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()

	source := &Source{}
	subs, errs := runSource(t, source, newTestSession(t, server, "example.com", 0), "example.com")
	assert.Empty(t, subs)
	assert.Empty(t, errs)
	assert.Zero(t, hits.Load())
	assert.True(t, source.Statistics().Skipped)
}

func TestActiveDNSSource_Paginates(t *testing.T) {
	pages := map[string]string{
		"": `{"records":[
                        {"domain":"www.example.com","ip_address":"192.0.2.1"},
                        {"domain":"www.example.com","ip_address":"192.0.2.2"},
                        {"domain":"cdn.provider.net","aliases":[{"name":"static.example.com","chain":["static.example.com","edge.example.com"]}]}
                ],"has_more":true,"next_cursor":3}`,
		"3": `{"records":[{"domain":"mail.example.com"}],"has_more":false,"next_cursor":0}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/query", r.URL.Path)
		assert.Equal(t, "Bearer adns_test", r.Header.Get("Authorization"))
		assert.Equal(t, "*.example.com", r.URL.Query().Get("q"))
		body, ok := pages[r.URL.Query().Get("cursor")]
		if !ok {
			http.Error(w, "unexpected cursor", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, body)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"adns_test"})
	subs, errs := runSource(t, source, newTestSession(t, server, "example.com", 0), "example.com")
	assert.Empty(t, errs)
	assert.Equal(t, []string{"www.example.com", "static.example.com", "edge.example.com", "mail.example.com"}, subs)

	stats := source.Statistics()
	assert.Equal(t, 2, stats.Requests)
	assert.Equal(t, 4, stats.Results)
}

func TestActiveDNSSource_MaxResultsStopsPaging(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprint(w, `{"records":[{"domain":"a.example.com"},{"domain":"b.example.com"}],"has_more":true,"next_cursor":2}`)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"adns_test"})
	subs, errs := runSource(t, source, newTestSession(t, server, "example.com", 1), "example.com")
	assert.Empty(t, errs)
	assert.Equal(t, []string{"a.example.com"}, subs)
	assert.Equal(t, int32(1), hits.Load())
}

func TestActiveDNSSource_StuckCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"records":[{"domain":"a.example.com"}],"has_more":true,"next_cursor":0}`)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"adns_test"})
	subs, errs := runSource(t, source, newTestSession(t, server, "example.com", 0), "example.com")
	assert.Equal(t, []string{"a.example.com"}, subs)
	require.Len(t, errs, 1)
	assert.Equal(t, 1, source.Statistics().Errors)
}

func TestActiveDNSSource_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, `{"error":"hourly budget exceeded","code":429,"exceeded":"hour"}`)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"adns_test"})
	subs, errs := runSource(t, source, newTestSession(t, server, "example.com", 0), "example.com")
	assert.Empty(t, subs)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "429")
}

func TestActiveDNSSource_CursorCapEndsPaging(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"error":"cursor beyond your policy's limit of 1000; narrow the query instead","code":400}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"records":[{"domain":"a.example.com"}],"has_more":true,"next_cursor":100}`)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"adns_test"})
	subs, errs := runSource(t, source, newTestSession(t, server, "example.com", 0), "example.com")
	assert.Equal(t, []string{"a.example.com"}, subs)
	assert.Empty(t, errs)
	assert.Equal(t, 2, source.Statistics().Requests)
	assert.Zero(t, source.Statistics().Errors)
}
