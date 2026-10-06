package sources_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// trackedBody reports whether the consumer closed it.
type trackedBody struct {
	io.Reader
	mu     sync.Mutex
	closed bool
}

func (b *trackedBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

func (b *trackedBody) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// A source must close every response body it is handed, including on the error
// path. httpRequestWrapper returns the response *and* an error for any non-200
// status, so a source that returns on `err != nil` without draining leaks the
// connection for every rate-limited or unauthorized reply, which is the common
// case for a key-based source.
func TestSourcesCloseResponseBodyOnErrorStatus(t *testing.T) {
	// 429 is what an exhausted free-tier key returns; 403 is what a rejected one
	// returns, and some sources retry on it down a separate path.
	statuses := []int{http.StatusTooManyRequests, http.StatusForbidden}

	for _, source := range concurrencySources() {
		t.Run(source.Name(), func(t *testing.T) {
			for _, status := range statuses {
				t.Run(http.StatusText(status), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					var mu sync.Mutex
					var bodies []*trackedBody

					transport := transportFunc(func(req *http.Request) (*http.Response, error) {
						body := &trackedBody{Reader: strings.NewReader(`{"error":"denied"}`)}
						mu.Lock()
						bodies = append(bodies, body)
						mu.Unlock()
						return &http.Response{
							StatusCode: status,
							Status:     http.StatusText(status),
							Body:       body,
							Header:     http.Header{"Content-Type": []string{"application/json"}},
							Request:    req,
						}, nil
					})

					source.AddApiKeys(concurrencyKeys(source.Name()))
					mockChaosClient(t, source, transport)
					awaitRun(t, ctx, startRun(t, ctx, source, "example.com", transport, 0))

					mu.Lock()
					defer mu.Unlock()
					for i, body := range bodies {
						if !body.isClosed() {
							t.Errorf("response body %d was never closed: the connection cannot be reused", i)
						}
					}
				})
			}
		})
	}
}
