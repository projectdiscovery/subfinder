package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type immediateLimiter struct{}

func (immediateLimiter) Wait(ctx context.Context, _ string) error { return ctx.Err() }

// A rate-limit retry is bounded per URL, not per run. Every page here answers
// 403 once and then 200, which is what a pool holding one exhausted token and
// one healthy token looks like. Counting those 403s across the whole run let
// the budget run out on a later page even though a working token was still in
// the pool, so enumeration stopped early and reported that every token was
// rate limited when none of them was.
func TestRateLimitRetryBudgetIsPerURL(t *testing.T) {
	const pages = 3

	var mu sync.Mutex
	seen := map[string]int{}

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		key := req.URL.Path + "?" + req.URL.RawQuery

		mu.Lock()
		seen[key]++
		n := seen[key]
		mu.Unlock()

		header := http.Header{"Content-Type": []string{"application/json"}}

		// First visit to a page: the token in hand is exhausted.
		if n == 1 {
			header.Set("X-Ratelimit-Remaining", "0")
			header.Set("Retry-After", "0")
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Status:     http.StatusText(http.StatusForbidden),
				Body:       io.NopCloser(strings.NewReader(`{"message":"rate limited"}`)),
				Header:     header,
				Request:    req,
			}, nil
		}

		// Second visit: the next token works. Hand out a next link until the
		// last page so the source walks the whole pagination chain.
		page := pageOf(key)
		if page < pages {
			header.Set("Link", fmt.Sprintf(`<https://api.github.com/search/code?page=%d>; rel="next"`, page+1))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     http.StatusText(http.StatusOK),
			Body:       io.NopCloser(strings.NewReader(`{"total_count":0,"items":[]}`)),
			Header:     header,
			Request:    req,
		}, nil
	})

	extractor, err := subscraping.NewSubdomainExtractor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	session := &subscraping.Session{
		Client:         &http.Client{Transport: transport},
		RequestLimiter: immediateLimiter{},
		Extractor:      extractor,
	}

	source := &Source{}
	// Two tokens: one 403 per page must be survivable on every page.
	source.apiKeys = []string{"token-a", "token-b"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, source.Name())

	var run runState
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)
		tokens := NewTokenManager(source.apiKeys)
		searchURL := "https://api.github.com/search/code?page=1"
		source.enumerate(ctx, searchURL, regexp.MustCompile(`example\.com`), tokens, session, results, &run, 0)
	}()

	var errs int
	for result := range results {
		if result.Type == subscraping.Error {
			errs++
			t.Logf("error result: %v", result.Error)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for page := 1; page <= pages; page++ {
		key := fmt.Sprintf("/search/code?page=%d", page)
		if got := seen[key]; got != 2 {
			t.Errorf("page %d was requested %d time(s), want 2 (one 403 then one 200): "+
				"the retry budget leaked across pages", page, got)
		}
	}
	if errs != 0 {
		t.Errorf("got %d error result(s), want 0: a healthy token was still in the pool", errs)
	}
}

func pageOf(key string) int {
	var page int
	if _, err := fmt.Sscanf(key, "/search/code?page=%d", &page); err != nil {
		return 0
	}
	return page
}
