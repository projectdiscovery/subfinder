package passive

import (
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/require"
)

func TestResolveRateLimitUsesGlobalWhenNoSourceOverride(t *testing.T) {
	maxCount, duration := resolveRateLimit(7, "sitedossier", nil)

	require.Equal(t, uint(7), maxCount)
	require.Equal(t, time.Second, duration)
}

func TestResolveRateLimitUsesSourceSpecificDuration(t *testing.T) {
	custom := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimit]{
			Map: map[string]subscraping.RateLimit{
				"sitedossier": {
					MaxCount: 2,
					Duration: time.Minute,
				},
			},
		},
	}

	maxCount, duration := resolveRateLimit(10, "sitedossier", custom)

	require.Equal(t, uint(2), maxCount)
	require.Equal(t, time.Minute, duration)
}

func TestResolveRateLimitSupportsSourceLimitWithoutGlobal(t *testing.T) {
	custom := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimit]{
			Map: map[string]subscraping.RateLimit{
				"sitedossier": {
					MaxCount: 8,
					Duration: time.Minute,
				},
			},
		},
	}

	maxCount, duration := resolveRateLimit(0, "sitedossier", custom)

	require.Equal(t, uint(8), maxCount)
	require.Equal(t, time.Minute, duration)
}

func TestResolveRateLimitReturnsUnlimitedWhenUnset(t *testing.T) {
	custom := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimit]{
			Map: map[string]subscraping.RateLimit{
				"crtsh": {
					MaxCount: 4,
					Duration: time.Second,
				},
			},
		},
	}

	maxCount, duration := resolveRateLimit(0, "sitedossier", custom)

	require.Zero(t, maxCount)
	require.Zero(t, duration)
}

func TestResolveRateLimitDefaultsToSecondsWhenDurationMissing(t *testing.T) {
	custom := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimit]{
			Map: map[string]subscraping.RateLimit{
				"sitedossier": {
					MaxCount: 3,
				},
			},
		},
	}

	maxCount, duration := resolveRateLimit(0, "sitedossier", custom)

	require.Equal(t, uint(3), maxCount)
	require.Equal(t, time.Second, duration)
}
