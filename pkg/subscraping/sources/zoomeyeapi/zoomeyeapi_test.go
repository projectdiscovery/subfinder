package zoomeyeapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

func newTestSession(t *testing.T, server *httptest.Server) *subscraping.Session {
	t.Helper()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)

	mrl, err := ratelimit.NewMultiLimiter(context.Background(), &ratelimit.Options{
		Key:         "zoomeyeapi",
		IsUnlimited: false,
		MaxCount:    math.MaxInt32,
		Duration:    time.Millisecond,
	})
	require.NoError(t, err)

	return &subscraping.Session{
		Client:           &http.Client{Transport: &rewriteTransport{target: target}, Timeout: 5 * time.Second},
		MultiRateLimiter: mrl,
	}
}

func runSource(t *testing.T, source *Source, session *subscraping.Session, domain string) (subs []string, errs []error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "zoomeyeapi")

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

type searchRequest struct {
	Query    string `json:"qbase64"`
	Page     int    `json:"page"`
	PageSize int    `json:"pagesize"`
	Fields   string `json:"fields"`
	SubType  string `json:"sub_type"`
}

func decodeSearchRequest(t *testing.T, r *http.Request) searchRequest {
	t.Helper()
	assert.Equal(t, http.MethodPost, r.Method)
	assert.Equal(t, "/v2/search", r.URL.Path)
	assert.Equal(t, "test-key", r.Header.Get("API-KEY"))
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	var req searchRequest
	require.NoError(t, json.Unmarshal(body, &req))
	return req
}

func TestZoomeyeAPISource_Metadata(t *testing.T) {
	source := &Source{}
	assert.Equal(t, "zoomeyeapi", source.Name())
	assert.False(t, source.IsDefault())
	assert.False(t, source.HasRecursiveSupport())
	assert.True(t, source.NeedsKey())
}

func TestZoomeyeAPISource_NoApiKey(t *testing.T) {
	source := &Source{}
	ctx := context.Background()
	mrl, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
		Key:         "zoomeyeapi",
		IsUnlimited: false,
		MaxCount:    math.MaxInt32,
		Duration:    time.Millisecond,
	})
	require.NoError(t, err)
	session := &subscraping.Session{Client: http.DefaultClient, MultiRateLimiter: mrl}

	subs, errs := runSource(t, source, session, "example.com")
	assert.Empty(t, subs)
	assert.Empty(t, errs)
	assert.True(t, source.Statistics().Skipped)
	assert.Equal(t, 0, source.Statistics().Requests)
}

func TestZoomeyeAPISource_PostsV2SearchBody(t *testing.T) {
	var got searchRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = decodeSearchRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":60000,"total":0,"data":[]}`))
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"zoomeye.ai:test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server), "example.com")

	assert.Empty(t, errs)
	assert.Empty(t, subs)
	assert.Equal(t, 1, got.Page)
	assert.Equal(t, 1000, got.PageSize)
	assert.Equal(t, "domain", got.Fields)
	assert.Equal(t, "web", got.SubType)
	q, err := base64.StdEncoding.DecodeString(got.Query)
	require.NoError(t, err)
	assert.Equal(t, `domain="example.com"`, string(q))
	assert.Equal(t, 1, source.Statistics().Requests)
}

func TestZoomeyeAPISource_EmitsDomainsAndSkipsEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = decodeSearchRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":60000,"total":2,"data":[{"domain":"a.example.com"},{"domain":""},{"domain":"b.example.com"}]}`))
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"zoomeye.ai:test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server), "example.com")

	assert.Empty(t, errs)
	assert.Equal(t, []string{"a.example.com", "b.example.com"}, subs)
	assert.Equal(t, 2, source.Statistics().Results)
}

func TestZoomeyeAPISource_NonSuccessCodeIsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":50000,"total":0,"data":[]}`))
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"zoomeye.ai:test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server), "example.com")

	assert.Empty(t, subs)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "50000")
	assert.Equal(t, 1, source.Statistics().Errors)
	assert.Equal(t, 1, source.Statistics().Requests)
}

func TestZoomeyeAPISource_HTTPErrorIsReported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"zoomeye.ai:test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server), "example.com")

	assert.Empty(t, subs)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "502")
	assert.Equal(t, 1, source.Statistics().Errors)
}

func TestZoomeyeAPISource_StopsOnLastPage(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		req := decodeSearchRequest(t, r)
		assert.Equal(t, int(n), req.Page)
		w.Header().Set("Content-Type", "application/json")
		// pageSize is 1000, so total 1001 requires two pages.
		_, _ = fmt.Fprintf(w, `{"code":60000,"total":1001,"data":[{"domain":"p%d.example.com"}]}`, n)
	}))
	defer server.Close()

	source := &Source{}
	source.AddApiKeys([]string{"zoomeye.ai:test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server), "example.com")

	assert.Empty(t, errs)
	assert.Equal(t, []string{"p1.example.com", "p2.example.com"}, subs)
	assert.Equal(t, 2, source.Statistics().Requests)
	assert.Equal(t, int32(2), atomic.LoadInt32(&hits))
}
