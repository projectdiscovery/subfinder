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

func TestBuildMultiRateLimiter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("NilCustomRateLimitDoesNotPanic", func(t *testing.T) {
		agent := New([]string{"crtsh"}, []string{}, false, false)
		mrl, err := agent.buildMultiRateLimiter(ctx, 1, nil)
		require.NoError(t, err)
		require.NotNil(t, mrl)
	})

	t.Run("GlobalRateLimitAppliedWhenSourceNotInCustom", func(t *testing.T) {
		agent := New([]string{"crtsh", "hackertarget"}, []string{}, false, false)
		customRL := &subscraping.CustomRateLimit{
			Custom: mapsutil.SyncLockMap[string, uint]{Map: make(map[string]uint)},
		}
		_ = customRL.Custom.Set("crtsh", 2)

		mrl, err := agent.buildMultiRateLimiter(ctx, 3, customRL)
		require.NoError(t, err)
		require.NotNil(t, mrl)
	})

	t.Run("NegativeGlobalRateLimitClampsToZero", func(t *testing.T) {
		agent := New([]string{"crtsh"}, []string{}, false, false)
		customRL := &subscraping.CustomRateLimit{
			Custom: mapsutil.SyncLockMap[string, uint]{Map: make(map[string]uint)},
		}

		mrl, err := agent.buildMultiRateLimiter(ctx, -5, customRL)
		require.NoError(t, err)
		require.NotNil(t, mrl)
	})

	t.Run("UnlimitedGlobalRateLimitBehavesLikeUnlimited", func(t *testing.T) {
		agent := New([]string{"crtsh"}, []string{}, false, false)

		mrl, err := agent.buildMultiRateLimiter(ctx, math.MaxInt32, nil)
		require.NoError(t, err)
		require.NotNil(t, mrl)
	})
}
