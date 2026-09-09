package passive

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type limiterTransport struct{}

func (limiterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header), Request: req}, nil
}

func TestSharedRateLimiterCanceledRequests(t *testing.T) {
	agent := &Agent{sources: []subscraping.Source{&blockingSource{}}}
	crl := newCustomRateLimit(map[string]uint{"mock": 1}, map[string]time.Duration{"mock": 200 * time.Millisecond})
	limiter := testRateLimiter(t, agent, 0, crl)
	if err := limiter.Wait(context.Background(), "mock"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), subscraping.CtxSourceArg, "mock"), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session := &subscraping.Session{RequestLimiter: limiter, Client: &http.Client{Transport: limiterTransport{}}}
			response, err := session.SimpleGet(ctx, "https://mock.invalid")
			if response != nil {
				session.DiscardHTTPResponse(response)
			}
			if err == nil {
				t.Error("canceled request succeeded")
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("expired requests waited for provider refills: %s", elapsed)
	}
}

func TestSharedRateLimiterBurstAndCancellation(t *testing.T) {
	agent := &Agent{sources: []subscraping.Source{&blockingSource{}}}
	limiter := testRateLimiter(t, agent, 100, newCustomRateLimit(map[string]uint{"mock": 2}, map[string]time.Duration{"mock": 100 * time.Millisecond}))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	successful := make(chan struct{}, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.Wait(ctx, "mock") == nil {
				successful <- struct{}{}
			}
		}()
	}
	wg.Wait()
	if len(successful) != 2 {
		t.Fatalf("initial burst=%d, want 2", len(successful))
	}
	// Expired waiters must not reserve tokens in the next window.
	next, cancelNext := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelNext()
	for range 2 {
		if err := limiter.Wait(next, "mock"); err != nil {
			t.Fatal(err)
		}
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := limiter.Wait(canceled, "mock"); err != context.Canceled {
		t.Fatalf("canceled wait=%v", err)
	}
	if err := limiter.Wait(context.Background(), "missing"); err == nil {
		t.Fatal("missing source accepted")
	}
}

func TestSharedRateLimiterUnlimited(t *testing.T) {
	agent := &Agent{sources: []subscraping.Source{&blockingSource{}}}
	limiter := testRateLimiter(t, agent, 0, nil)
	for range 100 {
		if err := limiter.Wait(context.Background(), "mock"); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.Wait(ctx, "mock"); err != context.Canceled {
		t.Fatalf("unlimited canceled wait=%v", err)
	}
}

type requestingSource struct{ blockingSource }

func (s *requestingSource) Run(ctx context.Context, _ string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	session.Client.Transport = limiterTransport{}
	go func() {
		defer close(results)
		response, err := session.SimpleGet(ctx, "https://mock.invalid")
		if response != nil {
			session.DiscardHTTPResponse(response)
		}
		if err != nil {
			results <- subscraping.Result{Type: subscraping.Error, Error: err}
		}
	}()
	return results
}
func TestSharedRateLimiterEnumerationDeadline(t *testing.T) {
	agent := &Agent{sources: []subscraping.Source{&requestingSource{}}}
	limiter := testRateLimiter(t, agent, 0, newCustomRateLimit(map[string]uint{"mock": 1}, map[string]time.Duration{"mock": time.Second}))
	if err := limiter.Wait(context.Background(), "mock"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range agent.EnumerateSubdomains("example.com", "", 0, 1, 20*time.Millisecond, WithRateLimiter(limiter)) {
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("domain deadlines waited for refill: %s", elapsed)
	}
}

func testRateLimiter(t *testing.T, agent *Agent, global int, custom *subscraping.CustomRateLimit) *RateLimiter {
	t.Helper()
	limiter, err := agent.NewRateLimiter(context.Background(), global, custom)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = limiter.Close() })
	return limiter
}
