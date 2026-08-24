package crtname

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
		Key:         "crtname",
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
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, "crtname")

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

func TestCrtnameSource_Metadata(t *testing.T) {
	source := &Source{}
	assert.Equal(t, "crtname", source.Name())
	assert.True(t, source.IsDefault())
	assert.False(t, source.HasRecursiveSupport())
	assert.False(t, source.NeedsKey())
	assert.Equal(t, subscraping.OptionalKey, source.KeyRequirement())
}

func TestCrtnameSource_ParsesPlaintext(t *testing.T) {
	const domain = "hackerone.com"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/search", r.URL.Path)
		assert.Equal(t, domain, r.URL.Query().Get("apex"))
		assert.Equal(t, "subfinder", r.Header.Get("User-Agent"))
		assert.Empty(t, r.Header.Get("Authorization"))
		fmt.Fprint(w, "www.hackerone.com\napi.hackerone.com\n\n*.hackerone.com\nhackerone.com\n")
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, errs)
	assert.ElementsMatch(t, []string{"www.hackerone.com", "api.hackerone.com"}, subs)
	assert.Equal(t, 2, source.Statistics().Results)
	assert.Equal(t, 1, source.Statistics().Requests)
	assert.Equal(t, 0, source.Statistics().Errors)
}

func TestCrtnameSource_EmptyBody(t *testing.T) {
	const domain = "hackerone.com"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, errs)
	assert.Empty(t, subs)
}

func TestCrtnameSource_NonOKStatus(t *testing.T) {
	const domain = "www.example.com"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid apex: not an apex (eTLD+1 is example.com)", http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, subs)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "400")
	assert.Equal(t, 1, source.Statistics().Errors)
}

func TestCrtnameSource_MaxResults(t *testing.T) {
	const domain = "hackerone.com"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "a.hackerone.com\nb.hackerone.com\nc.hackerone.com\nd.hackerone.com\n")
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 2), domain)

	assert.Empty(t, errs)
	assert.Equal(t, []string{"a.hackerone.com", "b.hackerone.com"}, subs)
	assert.Equal(t, 2, source.Statistics().Results)
}

func TestCrtnameSource_SendsBearerToken(t *testing.T) {
	const domain = "hackerone.com"
	var gotAuth atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		fmt.Fprint(w, "www.hackerone.com\n")
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	source.AddApiKeys([]string{"test-token"})
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, errs)
	assert.Equal(t, []string{"www.hackerone.com"}, subs)
	assert.Equal(t, "Bearer test-token", gotAuth.Load())
}

func TestCrtnameSource_ContextCancel(t *testing.T) {
	const domain = "hackerone.com"
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(2 * time.Second)
		fmt.Fprint(w, "www.hackerone.com\n")
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	session := newTestSession(t, server, domain, 0)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, "crtname")

	results := source.Run(ctx, domain, session)
	<-started
	cancel()

	var got []subscraping.Result
	for r := range results {
		got = append(got, r)
	}
	for _, r := range got {
		if r.Type == subscraping.Subdomain {
			t.Fatalf("got subdomain after cancel: %s", r.Value)
		}
	}
}
