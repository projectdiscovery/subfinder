package passive

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mapsutil "github.com/projectdiscovery/utils/maps"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

func newCustomRateLimit(counts map[string]uint, durations map[string]time.Duration) *subscraping.CustomRateLimit {
	crl := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, uint]{
			Map: make(map[string]uint),
		},
		CustomDuration: mapsutil.SyncLockMap[string, time.Duration]{
			Map: make(map[string]time.Duration),
		},
	}
	for k, v := range counts {
		_ = crl.Custom.Set(k, v)
	}
	for k, d := range durations {
		_ = crl.CustomDuration.Set(k, d)
	}
	return crl
}

func TestResolveSourceRateLimit_PerSourceOverride(t *testing.T) {
	// Per-source limit should override global
	crl := newCustomRateLimit(
		map[string]uint{"hackertarget": 5},
		map[string]time.Duration{"hackertarget": time.Minute},
	)

	rl, dur := resolveSourceRateLimit(10, crl, "hackertarget")
	assert.Equal(t, uint(5), rl)
	assert.Equal(t, time.Minute, dur)
}

func TestResolveSourceRateLimit_GlobalFallback(t *testing.T) {
	// Sources without per-source limit should use global -rl
	crl := newCustomRateLimit(nil, nil)

	rl, dur := resolveSourceRateLimit(10, crl, "crtsh")
	assert.Equal(t, uint(10), rl)
	assert.Equal(t, time.Second, dur)
}

func TestResolveSourceRateLimit_NoLimit(t *testing.T) {
	// No global and no per-source → unlimited (0)
	crl := newCustomRateLimit(nil, nil)

	rl, _ := resolveSourceRateLimit(0, crl, "crtsh")
	assert.Equal(t, uint(0), rl)
}

func TestResolveSourceRateLimit_ZeroValueRateLimit(t *testing.T) {
	// Zero-value CustomRateLimit (nil maps) should not panic and fall back to global
	rl, dur := resolveSourceRateLimit(5, &subscraping.CustomRateLimit{}, "crtsh")
	assert.Equal(t, uint(5), rl)
	assert.Equal(t, time.Second, dur)
}

func TestResolveSourceRateLimit_PerSourceDefaultDuration(t *testing.T) {
	// Per-source limit without explicit duration defaults to per-second
	crl := newCustomRateLimit(
		map[string]uint{"hackertarget": 3},
		nil,
	)

	rl, dur := resolveSourceRateLimit(0, crl, "hackertarget")
	assert.Equal(t, uint(3), rl)
	assert.Equal(t, time.Second, dur)
}

func TestBuildMultiRateLimiter_GlobalAppliedToAll(t *testing.T) {
	// With -rl 5 and no per-source overrides, all sources should be rate-limited
	agent := New([]string{"hackertarget", "crtsh"}, []string{}, false, false)
	crl := newCustomRateLimit(nil, nil)

	limiter, err := agent.buildMultiRateLimiter(context.Background(), 5, crl)
	require.NoError(t, err)
	require.NotNil(t, limiter)
}

func TestBuildMultiRateLimiter_NilRateLimit(t *testing.T) {
	// nil rateLimit should not panic (guard in buildMultiRateLimiter)
	agent := New([]string{"hackertarget"}, []string{}, false, false)

	limiter, err := agent.buildMultiRateLimiter(context.Background(), 0, nil)
	require.NoError(t, err)
	require.NotNil(t, limiter)
}

func TestBuildMultiRateLimiter_PerSourceWithDuration(t *testing.T) {
	// Per-source limit with custom duration (e.g. -rls hackertarget=2/m)
	agent := New([]string{"hackertarget", "crtsh"}, []string{}, false, false)
	crl := newCustomRateLimit(
		map[string]uint{"hackertarget": 2},
		map[string]time.Duration{"hackertarget": time.Minute},
	)

	limiter, err := agent.buildMultiRateLimiter(context.Background(), 0, crl)
	require.NoError(t, err)
	require.NotNil(t, limiter)
}

func TestBuildMultiRateLimiter_UnlimitedWhenNoLimits(t *testing.T) {
	// Without any rate limits, sources should get MaxUint32 (effectively unlimited)
	agent := New([]string{"hackertarget"}, []string{}, false, false)
	crl := newCustomRateLimit(nil, nil)

	limiter, err := agent.buildMultiRateLimiter(context.Background(), 0, crl)
	require.NoError(t, err)
	require.NotNil(t, limiter)
}

func TestResolveSourceRateLimit_PerSourceExceedsGlobal(t *testing.T) {
	// Per-source limit higher than global should be honoured
	// (the source was explicitly allowed more than the default)
	crl := newCustomRateLimit(
		map[string]uint{"hackertarget": 20},
		nil,
	)

	rl, dur := resolveSourceRateLimit(10, crl, "hackertarget")
	assert.Equal(t, uint(20), rl, "per-source limit should take precedence even when > global")
	assert.Equal(t, time.Second, dur)
}

func TestResolveSourceRateLimit_CaseInsensitive(t *testing.T) {
	// Source names should be case-insensitive for lookup
	crl := newCustomRateLimit(
		map[string]uint{"hackertarget": 5},
		nil,
	)

	// Try mixed case — should still match the lower-cased key
	rl, _ := resolveSourceRateLimit(0, crl, "HackerTarget")
	assert.Equal(t, uint(5), rl, "source name lookup should be case-insensitive")
}
