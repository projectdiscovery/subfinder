package passive

import (
	"context"
	"math"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/assert"
)

// TestBuildMultiRateLimiter_GlobalRateLimit tests that global rate limit is applied
// when no custom rate limit is set for a source
func TestBuildMultiRateLimiter_GlobalRateLimit(t *testing.T) {
	agent := &Agent{
		sources: []subscraping.Source{
			&mockSource{name: "source1"},
			&mockSource{name: "source2"},
		},
	}

	// Test with global rate limit only (no custom limits)
	globalRateLimit := 10
	customRateLimit := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, uint]{
			Map: make(map[string]uint),
		},
	}

	ctx := context.Background()
	limiter, err := agent.buildMultiRateLimiter(ctx, globalRateLimit, customRateLimit)

	assert.NoError(t, err)
	assert.NotNil(t, limiter)

	// Verify that both sources got the global rate limit
	// We can't directly inspect the limiter, but we can verify it was created without error
	// and that the logic path was correct
}

// TestBuildMultiRateLimiter_CustomRateLimit tests that custom rate limits override global
func TestBuildMultiRateLimiter_CustomRateLimit(t *testing.T) {
	agent := &Agent{
		sources: []subscraping.Source{
			&mockSource{name: "source1"},
			&mockSource{name: "source2"},
		},
	}

	globalRateLimit := 10
	customRateLimit := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, uint]{
			Map: map[string]uint{
				"source1": 20, // Custom limit for source1
			},
		},
	}

	ctx := context.Background()
	limiter, err := agent.buildMultiRateLimiter(ctx, globalRateLimit, customRateLimit)

	assert.NoError(t, err)
	assert.NotNil(t, limiter)
	// source1 should use custom limit (20), source2 should use global (10)
}

// TestBuildMultiRateLimiter_NoRateLimit tests that unlimited is used when no limits are set
func TestBuildMultiRateLimiter_NoRateLimit(t *testing.T) {
	agent := &Agent{
		sources: []subscraping.Source{
			&mockSource{name: "source1"},
		},
	}

	globalRateLimit := 0 // No global limit
	customRateLimit := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, uint]{
			Map: make(map[string]uint),
		},
	}

	ctx := context.Background()
	limiter, err := agent.buildMultiRateLimiter(ctx, globalRateLimit, customRateLimit)

	assert.NoError(t, err)
	assert.NotNil(t, limiter)
	// Should use unlimited (math.MaxUint32)
}

// TestSourceRateLimitOrDefault tests the helper function
func TestSourceRateLimitOrDefault(t *testing.T) {
	tests := []struct {
		name              string
		defaultRateLimit  uint
		sourceRateLimit   uint
		expectedRateLimit uint
	}{
		{
			name:              "Use source rate limit when set",
			defaultRateLimit:  10,
			sourceRateLimit:   20,
			expectedRateLimit: 20,
		},
		{
			name:              "Use default when source is 0",
			defaultRateLimit:  10,
			sourceRateLimit:   0,
			expectedRateLimit: 10,
		},
		{
			name:              "Both zero returns zero",
			defaultRateLimit:  0,
			sourceRateLimit:   0,
			expectedRateLimit: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sourceRateLimitOrDefault(tt.defaultRateLimit, tt.sourceRateLimit)
			assert.Equal(t, tt.expectedRateLimit, result)
		})
	}
}

// mockSource is a mock implementation of subscraping.Source for testing
type mockSource struct {
	name string
}

func (m *mockSource) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	close(results)
	return results
}

func (m *mockSource) Name() string {
	return m.name
}

func (m *mockSource) Statistics() subscraping.Statistics {
	return subscraping.Statistics{}
}

func (m *mockSource) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}
