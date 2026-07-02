package passive

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// blockingSource emits results with bare (non ctx-aware) channel sends, like the
// real sources' error paths. Its goroutine only exits once every queued send has
// been received, so if the engine abandons the channel on cancel instead of
// draining it, the goroutine leaks and exited is never closed.
type blockingSource struct {
	exited chan struct{}
}

func (s *blockingSource) Run(_ context.Context, _ string, _ *subscraping.Session) <-chan subscraping.Result {
	ch := make(chan subscraping.Result)
	go func() {
		defer close(ch)
		defer close(s.exited)
		for i := 0; i < 100; i++ {
			ch <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: "a.example.com"}
		}
		// trailing bare error send, mirroring real sources
		ch <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: errors.New("boom")}
	}()
	return ch
}

func (s *blockingSource) Name() string                       { return "mock" }
func (s *blockingSource) IsDefault() bool                    { return true }
func (s *blockingSource) HasRecursiveSupport() bool          { return false }
func (s *blockingSource) NeedsKey() bool                     { return false }
func (s *blockingSource) AddApiKeys(_ []string)              {}
func (s *blockingSource) Statistics() subscraping.Statistics { return subscraping.Statistics{} }
func (s *blockingSource) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

// TestEnumerateDrainsSourcesOnCancel verifies that when enumeration is cancelled
// (max-enumeration-time) while a slow consumer is applying backpressure, the
// source goroutines are drained and exit instead of leaking on a blocked send.
func TestEnumerateDrainsSourcesOnCancel(t *testing.T) {
	mock := &blockingSource{exited: make(chan struct{})}
	agent := &Agent{sources: []subscraping.Source{mock}}

	// short max enumeration time so ctx cancels while the consumer is stalled
	results := agent.EnumerateSubdomainsWithCtx(context.Background(), "example.com", "", 0, 5, 150*time.Millisecond)

	// read a single result then stall the consumer, forcing the forwarder to
	// block on the outer send and the source to block on a bare send
	<-results
	time.Sleep(500 * time.Millisecond)

	// drain whatever remains; the channel is already closed by now
	for range results {
	}

	select {
	case <-mock.exited:
		// source goroutine exited cleanly: no leak
	case <-time.After(2 * time.Second):
		t.Fatal("source goroutine leaked: engine did not drain the source channel on cancel")
	}
}
