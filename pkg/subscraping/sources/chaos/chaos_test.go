package chaos

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLimiter(t *testing.T) *ratelimit.MultiLimiter {
	t.Helper()
	mrl, err := ratelimit.NewMultiLimiter(context.Background(), &ratelimit.Options{
		Key:         "chaos",
		IsUnlimited: false,
		MaxCount:    math.MaxInt32,
		Duration:    time.Millisecond,
	})
	require.NoError(t, err)
	return mrl
}

func setBaseURL(t *testing.T, u string) {
	t.Helper()
	old := baseURL
	baseURL = u
	t.Cleanup(func() { baseURL = old })
}

func runSource(t *testing.T, ctx context.Context, source *Source, session *subscraping.Session) (subs []string, errs []error) {
	t.Helper()
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, "chaos")
	for r := range source.Run(ctx, "example.com", session) {
		switch r.Type {
		case subscraping.Subdomain:
			subs = append(subs, r.Value)
		case subscraping.Error:
			errs = append(errs, r.Error)
		}
	}
	return subs, errs
}

func TestChaosSource_Results(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/dns/example.com/subdomains", r.URL.Path)
		assert.Equal(t, "test-key", r.Header.Get("Authorization"))
		// Keys may come in any order; the list is found by name.
		_, _ = fmt.Fprint(w, `{"count":2,"meta":{"x":[1,2]},"domain":"example.com","subdomains":["www","api.dev"],"next":{"cursor":null}}`)
	}))
	defer server.Close()
	setBaseURL(t, server.URL+"/dns")

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	session := &subscraping.Session{Client: server.Client(), MultiRateLimiter: newLimiter(t)}

	subs, errs := runSource(t, context.Background(), source, session)
	assert.Empty(t, errs)
	assert.Equal(t, []string{"www.example.com", "api.dev.example.com"}, subs)
	stats := source.Statistics()
	assert.Equal(t, 1, stats.Requests)
	assert.Equal(t, 2, stats.Results)
	assert.Equal(t, 0, stats.Errors)
}

// The request must go through the session client, so -proxy applies to it.
func TestChaosSource_UsesSessionProxy(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A forward proxy receives the absolute URL of the target.
		if r.URL.Host == "chaos.invalid" && r.URL.Path == "/dns/example.com/subdomains" {
			proxied.Add(1)
		}
		_, _ = fmt.Fprint(w, `{"domain":"example.com","subdomains":["www"]}`)
	}))
	defer proxy.Close()
	setBaseURL(t, "http://chaos.invalid/dns")

	session, err := subscraping.NewSession("example.com", proxy.URL, newLimiter(t), 5)
	require.NoError(t, err)
	defer session.Close()

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})

	subs, errs := runSource(t, context.Background(), source, session)
	assert.Empty(t, errs)
	assert.Equal(t, []string{"www.example.com"}, subs)
	assert.Equal(t, int32(1), proxied.Load(), "request did not go through the session proxy")
}

func TestChaosSource_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid key"}`, http.StatusUnauthorized)
	}))
	defer server.Close()
	setBaseURL(t, server.URL+"/dns")

	source := &Source{}
	source.AddApiKeys([]string{"bad-key"})
	session := &subscraping.Session{Client: server.Client(), MultiRateLimiter: newLimiter(t)}

	subs, errs := runSource(t, context.Background(), source, session)
	assert.Empty(t, subs)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "401")
	assert.Equal(t, 1, source.Statistics().Errors)
}

func TestChaosSource_MalformedBody(t *testing.T) {
	for name, body := range map[string]string{
		"not an object":           `["www"]`,
		"no subdomains":           `{"domain":"example.com"}`,
		"truncated list":          `{"subdomains":["www",`,
		"truncated after open":    `{"subdomains":[`,
		"truncated after element": `{"subdomains":["www"`,
		"truncated after list":    `{"subdomains":["www"]`,
		"truncated after key":     `{"subdomains":["www"],"count"`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, body)
			}))
			defer server.Close()
			setBaseURL(t, server.URL+"/dns")

			source := &Source{}
			source.AddApiKeys([]string{"test-key"})
			session := &subscraping.Session{Client: server.Client(), MultiRateLimiter: newLimiter(t)}

			_, errs := runSource(t, context.Background(), source, session)
			assert.Len(t, errs, 1)
		})
	}
}

func TestChaosSource_NoApiKey(t *testing.T) {
	source := &Source{}
	session := &subscraping.Session{Client: http.DefaultClient, MultiRateLimiter: newLimiter(t)}

	subs, errs := runSource(t, context.Background(), source, session)
	assert.Empty(t, subs)
	assert.Empty(t, errs)
	assert.True(t, source.Statistics().Skipped)
	assert.Equal(t, 0, source.Statistics().Requests)
}

// Cancelling the context while results are streaming must close the channel
// instead of leaving a goroutine blocked on a send.
func TestChaosSource_StopsOnCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		items := make([]string, 10000)
		for i := range items {
			items[i] = fmt.Sprintf(`"s%d"`, i)
		}
		_, _ = fmt.Fprintf(w, `{"subdomains":[%s]}`, strings.Join(items, ","))
	}))
	defer server.Close()
	setBaseURL(t, server.URL+"/dns")

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	session := &subscraping.Session{Client: server.Client(), MultiRateLimiter: newLimiter(t)}

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), subscraping.CtxSourceArg, "chaos"))
	results := source.Run(ctx, "example.com", session)
	<-results
	cancel()

	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("results channel was not closed after cancel")
	}
	assert.Less(t, source.Statistics().Results, 10000)
}
