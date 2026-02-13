package passive

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/require"
)

// stubSource is a minimal Source implementation for testing.
type stubSource struct {
	name string
}

func (s stubSource) Run(_ context.Context, _ string, _ *subscraping.Session) <-chan subscraping.Result {
	return nil
}
func (s stubSource) Name() string                    { return s.name }
func (s stubSource) IsDefault() bool                 { return true }
func (s stubSource) HasRecursiveSupport() bool       { return false }
func (s stubSource) KeyRequirement() subscraping.KeyRequirement { return subscraping.NoKey }
func (s stubSource) NeedsKey() bool                  { return false }
func (s stubSource) AddApiKeys(_ []string)           {}
func (s stubSource) Statistics() subscraping.Statistics {
	return subscraping.Statistics{}
}

func TestBuildMultiRateLimiter_RespectsSourceDuration(t *testing.T) {
	agent := &Agent{
		sources: []subscraping.Source{
			stubSource{name: "testsource"},
		},
	}

	crl := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitEntry]{
			Map: map[string]subscraping.RateLimitEntry{
				"testsource": {MaxCount: 2, Duration: time.Minute},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mrl, err := agent.buildMultiRateLimiter(ctx, 0, crl)
	require.NoError(t, err)
	defer mrl.Stop()

	// The limiter should allow 2 requests per minute. Verify that the
	// first two Take calls return immediately and the third blocks.
	start := time.Now()
	require.NoError(t, mrl.Take("testsource"))
	require.NoError(t, mrl.Take("testsource"))
	elapsed := time.Since(start)

	// First two tokens should be nearly instant (well under 1 second).
	require.Less(t, elapsed, 500*time.Millisecond,
		"first two tokens should be available immediately")

	// Third take should block for a significant portion of 30 seconds
	// (60s / 2 = 30s per token). We verify it blocks for at least 1 second,
	// which proves the duration is minutes not seconds (if it were per-second,
	// the third token would be available in ~500ms).
	done := make(chan struct{})
	go func() {
		_ = mrl.Take("testsource")
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("third Take returned immediately; duration not respected")
	case <-time.After(1 * time.Second):
		// Expected: the third token is blocked, proving per-minute rate limiting works.
	}
}

func TestBuildMultiRateLimiter_DefaultsToSecond(t *testing.T) {
	agent := &Agent{
		sources: []subscraping.Source{
			stubSource{name: "fastsource"},
		},
	}

	crl := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitEntry]{
			Map: map[string]subscraping.RateLimitEntry{
				"fastsource": {MaxCount: 10, Duration: time.Second},
			},
		},
	}

	ctx := context.Background()
	mrl, err := agent.buildMultiRateLimiter(ctx, 0, crl)
	require.NoError(t, err)
	defer mrl.Stop()

	// Should allow 10 requests per second — all should be available quickly.
	start := time.Now()
	for i := 0; i < 10; i++ {
		require.NoError(t, mrl.Take("fastsource"))
	}
	elapsed := time.Since(start)
	require.Less(t, elapsed, 2*time.Second,
		"10 tokens per second should be consumed quickly")
}

func TestBuildMultiRateLimiter_GlobalFallback(t *testing.T) {
	agent := &Agent{
		sources: []subscraping.Source{
			stubSource{name: "unconfigured"},
		},
	}

	// Empty custom rate limits — should use unlimited rate.
	crl := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitEntry]{
			Map: make(map[string]subscraping.RateLimitEntry),
		},
	}

	ctx := context.Background()
	mrl, err := agent.buildMultiRateLimiter(ctx, 0, crl)
	require.NoError(t, err)
	defer mrl.Stop()

	// Unlimited — should not block.
	start := time.Now()
	for i := 0; i < 100; i++ {
		require.NoError(t, mrl.Take("unconfigured"))
	}
	elapsed := time.Since(start)
	require.Less(t, elapsed, time.Second,
		"unlimited source should not throttle")
}
