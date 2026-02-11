package passive

import (
	"context"
	"testing"
	"time"

	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

func TestBuildMultiRateLimiter_PerSourceDuration(t *testing.T) {
	ctx := context.Background()
	agent := New([]string{"crtsh", "hackertarget"}, []string{}, false, false)

	customRL := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{
			Map: map[string]subscraping.RateLimitSpec{
				"crtsh":        {MaxCount: 2, Duration: time.Minute},
				"hackertarget": {MaxCount: 10, Duration: time.Second},
			},
		},
	}

	multiRateLimiter, err := agent.buildMultiRateLimiter(ctx, 0, customRL)
	require.NoError(t, err)
	require.NotNil(t, multiRateLimiter)
}

func TestBuildMultiRateLimiter_GlobalFallback(t *testing.T) {
	ctx := context.Background()
	agent := New([]string{"crtsh", "hackertarget"}, []string{}, false, false)

	// No per-source limits, only global
	customRL := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{
			Map: make(map[string]subscraping.RateLimitSpec),
		},
	}

	multiRateLimiter, err := agent.buildMultiRateLimiter(ctx, 5, customRL)
	require.NoError(t, err)
	require.NotNil(t, multiRateLimiter)
}

func TestBuildMultiRateLimiter_NilCustomRateLimit(t *testing.T) {
	ctx := context.Background()
	agent := New([]string{"crtsh"}, []string{}, false, false)

	// Should not panic when rateLimit is nil
	multiRateLimiter, err := agent.buildMultiRateLimiter(ctx, 5, nil)
	require.NoError(t, err)
	require.NotNil(t, multiRateLimiter)
}

func TestBuildMultiRateLimiter_NegativeGlobalClamped(t *testing.T) {
	ctx := context.Background()
	agent := New([]string{"crtsh"}, []string{}, false, false)

	customRL := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{
			Map: make(map[string]subscraping.RateLimitSpec),
		},
	}

	// Negative global rate limit should be clamped to zero (unlimited)
	multiRateLimiter, err := agent.buildMultiRateLimiter(ctx, -5, customRL)
	require.NoError(t, err)
	require.NotNil(t, multiRateLimiter)
}

func TestBuildMultiRateLimiter_PerSourceOverridesGlobal(t *testing.T) {
	ctx := context.Background()
	agent := New([]string{"crtsh", "hackertarget"}, []string{}, false, false)

	// crtsh has per-source limit, hackertarget should fall back to global
	customRL := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{
			Map: map[string]subscraping.RateLimitSpec{
				"crtsh": {MaxCount: 2, Duration: time.Minute},
			},
		},
	}

	multiRateLimiter, err := agent.buildMultiRateLimiter(ctx, 10, customRL)
	require.NoError(t, err)
	require.NotNil(t, multiRateLimiter)
}

func TestBuildMultiRateLimiter_ZeroGlobalNoPerSource(t *testing.T) {
	ctx := context.Background()
	agent := New([]string{"crtsh"}, []string{}, false, false)

	// No global, no per-source → unlimited
	customRL := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimitSpec]{
			Map: make(map[string]subscraping.RateLimitSpec),
		},
	}

	multiRateLimiter, err := agent.buildMultiRateLimiter(ctx, 0, customRL)
	require.NoError(t, err)
	require.NotNil(t, multiRateLimiter)
}
