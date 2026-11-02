package windvane

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rewriteTransport sends every request to the test server's host while
// preserving the original path, so the source's hardcoded windvane URL
// still resolves to our handler.
type rewriteTransport struct {
	target *url.URL
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = r.target.Scheme
	req.URL.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

// newPagedServer serves total subdomains split in pages of the requested
// count, with the page_response fields of the windvane API documentation,
// and records every requested page.
func newPagedServer(t *testing.T, total int) (*httptest.Server, func() []int) {
	t.Helper()
	var mu sync.Mutex
	var pages []int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PageRequest struct {
				Page  int `json:"page"`
				Count int `json:"count"`
			} `json:"page_request"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		page, count := req.PageRequest.Page, req.PageRequest.Count
		mu.Lock()
		pages = append(pages, page)
		mu.Unlock()

		var resp response
		for i := (page - 1) * count; i < min(page*count, total); i++ {
			resp.Data.List = append(resp.Data.List, domainEntry{Domain: fmt.Sprintf("sub%d.example.com", i)})
		}
		resp.Data.PageResponse = pageInfo{
			Total:     strconv.Itoa(total),
			Count:     strconv.Itoa(count),
			TotalPage: strconv.Itoa((total + count - 1) / count),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)

	return server, func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), pages...)
	}
}

func runSource(t *testing.T, server *httptest.Server) (subs []string, errs []error) {
	t.Helper()
	return runSourceWithLimit(t, server, 0)
}

func runSourceWithLimit(t *testing.T, server *httptest.Server, maxResults int) (subs []string, errs []error) {
	t.Helper()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)

	mrl, err := ratelimit.NewMultiLimiter(context.Background(), &ratelimit.Options{
		Key:         "windvane",
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
	ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, "windvane")

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	for r := range source.Run(ctxWithValue, "example.com", session) {
		switch r.Type {
		case subscraping.Subdomain:
			subs = append(subs, r.Value)
		case subscraping.Error:
			errs = append(errs, r.Error)
		}
	}
	return subs, errs
}

// Pagination must stop after the last page instead of requesting one more
// empty page.
func TestWindvaneSource_StopsAfterLastPage(t *testing.T) {
	tests := []struct {
		name  string
		total int
		pages []int
	}{
		{name: "single page", total: 2, pages: []int{1}},
		{name: "full single page", total: 1000, pages: []int{1}},
		{name: "partial last page", total: 1500, pages: []int{1, 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, requestedPages := newPagedServer(t, tt.total)

			subs, errs := runSource(t, server)

			assert.Empty(t, errs)
			assert.Len(t, subs, tt.total)
			assert.Equal(t, tt.pages, requestedPages())
		})
	}
}

// With -max-results set, pagination must stop once the limit is reached
// instead of reading every page.
func TestWindvaneSource_HonorsMaxResults(t *testing.T) {
	tests := []struct {
		name       string
		maxResults int
		pages      []int
	}{
		{name: "limit ends a page", maxResults: 1000, pages: []int{1}},
		{name: "limit inside a page", maxResults: 1500, pages: []int{1, 2}},
		{name: "limit above the total", maxResults: 5000, pages: []int{1, 2, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, requestedPages := newPagedServer(t, 3000)

			subs, errs := runSourceWithLimit(t, server, tt.maxResults)

			assert.Empty(t, errs)
			assert.Len(t, subs, min(tt.maxResults, 3000))
			assert.Equal(t, tt.pages, requestedPages())
		})
	}
}
