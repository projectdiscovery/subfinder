package passive

import (
	"context"
	"math"
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

// TestBuildMultiRateLimiter_PerSourceLimit verifies that per-source rate limits
// from -rls are applied correctly (fixes issue #1434).
func TestBuildMultiRateLimiter_PerSourceLimit(t *testing.T) {
	agent := New([]string{"hackertarget", "crtsh"}, []string{}, false, false)

	crl := newCustomRateLimit(
		map[string]uint{"hackertarget": 5},
		map[string]time.Duration{"hackertarget": time.Minute},
	)

	mrl, err := agent.buildMultiRateLimiter(context.Background(), 0, crl)
	require.NoError(t, err)
	require.NotNil(t, mrl)

	// hackertarget should have 5 req/min
	limit, err := mrl.GetLimit("hackertarget")
	require.NoError(t, err)
	assert.Equal(t, uint(5), limit, "hackertarget should have 5 req per configured duration")

	// crtsh has no custom limit and no global limit => unlimited
	limit, err = mrl.GetLimit("crtsh")
	require.NoError(t, err)
	assert.Equal(t, uint(math.MaxUint32), limit, "crtsh should be unlimited when no rate limit is set")
}

// TestBuildMultiRateLimiter_GlobalRateLimit verifies that the global -rl flag
// is applied to sources that do not have a per-source override (fixes issue #1434).
func TestBuildMultiRateLimiter_GlobalRateLimit(t *testing.T) {
	agent := New([]string{"hackertarget", "crtsh", "sitedossier"}, []string{}, false, false)

	// hackertarget has a custom limit; crtsh and sitedossier should get the global limit
	crl := newCustomRateLimit(
		map[string]uint{"hackertarget": 10},
		map[string]time.Duration{"hackertarget": time.Second},
	)

	globalRateLimit := 3
	mrl, err := agent.buildMultiRateLimiter(context.Background(), globalRateLimit, crl)
	require.NoError(t, err)
	require.NotNil(t, mrl)

	// hackertarget uses its custom limit, not the global
	limit, err := mrl.GetLimit("hackertarget")
	require.NoError(t, err)
	assert.Equal(t, uint(10), limit, "hackertarget should use its per-source limit")

	// crtsh should receive the global rate limit
	limit, err = mrl.GetLimit("crtsh")
	require.NoError(t, err)
	assert.Equal(t, uint(globalRateLimit), limit, "crtsh should use the global rate limit when no per-source limit is set")

	// sitedossier should also receive the global rate limit
	limit, err = mrl.GetLimit("sitedossier")
	require.NoError(t, err)
	assert.Equal(t, uint(globalRateLimit), limit, "sitedossier should use the global rate limit when no per-source limit is set")
}

// TestBuildMultiRateLimiter_GlobalFallbackInCustomMap verifies that a source in
// the custom map with count 0 falls back to the global rate limit.
func TestBuildMultiRateLimiter_GlobalFallbackInCustomMap(t *testing.T) {
	agent := New([]string{"hackertarget"}, []string{}, false, false)

	// hackertarget has count 0 => falls back to global
	crl := newCustomRateLimit(
		map[string]uint{"hackertarget": 0},
		map[string]time.Duration{},
	)

	globalRateLimit := 7
	mrl, err := agent.buildMultiRateLimiter(context.Background(), globalRateLimit, crl)
	require.NoError(t, err)
	require.NotNil(t, mrl)

	limit, err := mrl.GetLimit("hackertarget")
	require.NoError(t, err)
	assert.Equal(t, uint(globalRateLimit), limit, "count-0 source should fall back to global rate limit")
}

// TestBuildMultiRateLimiter_NoLimits verifies that sources are unlimited when
// neither -rl nor -rls is set.
func TestBuildMultiRateLimiter_NoLimits(t *testing.T) {
	agent := New([]string{"hackertarget"}, []string{}, false, false)

	crl := newCustomRateLimit(map[string]uint{}, map[string]time.Duration{})

	mrl, err := agent.buildMultiRateLimiter(context.Background(), 0, crl)
	require.NoError(t, err)
	require.NotNil(t, mrl)

	limit, err := mrl.GetLimit("hackertarget")
	require.NoError(t, err)
	assert.Equal(t, uint(math.MaxUint32), limit, "source should be unlimited when no rate limit flags are set")
}
