package passive

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSourceRateLimitOrDefault(t *testing.T) {
	tests := []struct {
		name              string
		defaultRateLimit  uint
		sourceRateLimit   uint
		expectedRateLimit uint
	}{
		{"UseSourceLimit", 10, 5, 5},
		{"UseDefaultWhenSourceIsZero", 10, 0, 10},
		{"BothZero", 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sourceRateLimitOrDefault(tt.defaultRateLimit, tt.sourceRateLimit)
			assert.Equal(t, tt.expectedRateLimit, result)
		})
	}
}

func TestBuildMultiRateLimiter(t *testing.T) {
	ctx := context.Background()

	t.Run("GlobalRateLimitAppliedWhenNoCustomRateLimit", func(t *testing.T) {
		agent := New([]string{"crtsh"}, []string{}, false, false)
		customRL := &subscraping.CustomRateLimit{
			Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{Map: make(map[string]subscraping.RateLimitSpec)},
		}

		multiRateLimiter, err := agent.buildMultiRateLimiter(ctx, 10, customRL)

		require.NoError(t, err)
		require.NotNil(t, multiRateLimiter)
	})

	t.Run("CustomRateLimitOverridesGlobal", func(t *testing.T) {
		agent := New([]string{"crtsh"}, []string{}, false, false)
		customRL := &subscraping.CustomRateLimit{
			Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{Map: make(map[string]subscraping.RateLimitSpec)},
		}
		customRL.Custom.Set("crtsh", subscraping.RateLimitSpec{
			MaxCount: 5,
			Duration: time.Minute,
		})

		multiRateLimiter, err := agent.buildMultiRateLimiter(ctx, 10, customRL)

		require.NoError(t, err)
		require.NotNil(t, multiRateLimiter)
	})

	t.Run("CustomRateLimitZeroFallsBackToGlobal", func(t *testing.T) {
		agent := New([]string{"crtsh"}, []string{}, false, false)
		customRL := &subscraping.CustomRateLimit{
			Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{Map: make(map[string]subscraping.RateLimitSpec)},
		}
		customRL.Custom.Set("crtsh", subscraping.RateLimitSpec{
			MaxCount: 0,
			Duration: time.Second,
		})

		multiRateLimiter, err := agent.buildMultiRateLimiter(ctx, 15, customRL)

		require.NoError(t, err)
		require.NotNil(t, multiRateLimiter)
	})

	t.Run("GlobalRateLimitAppliedWhenSourceNotInCustom", func(t *testing.T) {
		agent := New([]string{"crtsh", "hackertarget"}, []string{}, false, false)
		customRL := &subscraping.CustomRateLimit{
			Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{Map: make(map[string]subscraping.RateLimitSpec)},
		}
		// Only set custom for crtsh, hackertarget should use global
		customRL.Custom.Set("crtsh", subscraping.RateLimitSpec{
			MaxCount: 5,
			Duration: time.Second,
		})

		multiRateLimiter, err := agent.buildMultiRateLimiter(ctx, 20, customRL)

		require.NoError(t, err)
		require.NotNil(t, multiRateLimiter)
	})
}
