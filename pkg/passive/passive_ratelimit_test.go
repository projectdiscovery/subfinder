package passive

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/require"
)

func TestBuildMultiRateLimiter_AppliesGlobalRateLimitWhenCustomMissing(t *testing.T) {
	agent := newTestAgent("source1", "source2")

	customRateLimit := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{
			Map: map[string]subscraping.RateLimitSpec{
				"source1": {
					MaxCount: 3,
					Duration: time.Second,
				},
			},
		},
	}

	multiRateLimiter, err := agent.buildMultiRateLimiter(context.Background(), 9, customRateLimit)
	require.NoError(t, err)
	require.NotNil(t, multiRateLimiter)
	t.Cleanup(func() {
		multiRateLimiter.Stop()
	})

	source1Limit, err := multiRateLimiter.GetLimit("source1")
	require.NoError(t, err)
	require.Equal(t, uint(3), source1Limit)

	source2Limit, err := multiRateLimiter.GetLimit("source2")
	require.NoError(t, err)
	require.Equal(t, uint(9), source2Limit)
}

func TestBuildMultiRateLimiter_AppliesGlobalRateLimitWhenCustomIsNil(t *testing.T) {
	agent := newTestAgent("source1")

	multiRateLimiter, err := agent.buildMultiRateLimiter(context.Background(), 7, nil)
	require.NoError(t, err)
	require.NotNil(t, multiRateLimiter)
	t.Cleanup(func() {
		multiRateLimiter.Stop()
	})

	limit, err := multiRateLimiter.GetLimit("source1")
	require.NoError(t, err)
	require.Equal(t, uint(7), limit)
}

func TestBuildMultiRateLimiter_UsesCustomDuration(t *testing.T) {
	agent := newTestAgent("source1")

	customRateLimit := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{
			Map: map[string]subscraping.RateLimitSpec{
				"source1": {
					MaxCount: 2,
					Duration: 150 * time.Millisecond,
				},
			},
		},
	}

	multiRateLimiter, err := agent.buildMultiRateLimiter(context.Background(), 100, customRateLimit)
	require.NoError(t, err)
	require.NotNil(t, multiRateLimiter)
	t.Cleanup(func() {
		multiRateLimiter.Stop()
	})

	start := time.Now()
	require.NoError(t, multiRateLimiter.Take("source1"))
	require.NoError(t, multiRateLimiter.Take("source1"))
	require.NoError(t, multiRateLimiter.Take("source1"))
	elapsed := time.Since(start)

	require.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
}

func TestBuildMultiRateLimiter_UnlimitedWhenNoRateLimitProvided(t *testing.T) {
	agent := newTestAgent("source1")

	customRateLimit := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{
			Map: make(map[string]subscraping.RateLimitSpec),
		},
	}

	multiRateLimiter, err := agent.buildMultiRateLimiter(context.Background(), 0, customRateLimit)
	require.NoError(t, err)
	require.NotNil(t, multiRateLimiter)
	t.Cleanup(func() {
		multiRateLimiter.Stop()
	})

	limit, err := multiRateLimiter.GetLimit("source1")
	require.NoError(t, err)
	require.Equal(t, uint(math.MaxUint32), limit)
}

func TestSourceRateLimitOrDefault(t *testing.T) {
	require.Equal(t, uint(10), sourceRateLimitOrDefault(10, 0))
	require.Equal(t, uint(5), sourceRateLimitOrDefault(10, 5))
	require.Equal(t, uint(0), sourceRateLimitOrDefault(0, 0))
}

func newTestAgent(sourceNames ...string) *Agent {
	sources := make([]subscraping.Source, 0, len(sourceNames))
	for _, sourceName := range sourceNames {
		sources = append(sources, &testSource{name: sourceName})
	}
	return &Agent{sources: sources}
}

type testSource struct {
	name string
}

func (t *testSource) Run(context.Context, string, *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	close(results)
	return results
}

func (t *testSource) Name() string {
	return t.name
}

func (t *testSource) IsDefault() bool {
	return true
}

func (t *testSource) HasRecursiveSupport() bool {
	return false
}

func (t *testSource) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

func (t *testSource) NeedsKey() bool {
	return false
}

func (t *testSource) AddApiKeys([]string) {}

func (t *testSource) Statistics() subscraping.Statistics {
	return subscraping.Statistics{}
}
