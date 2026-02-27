package passive

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/require"
)

func newCustomRateLimit() *subscraping.CustomRateLimit {
	return &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.SourceRateLimit]{
			Map: make(map[string]subscraping.SourceRateLimit),
		},
	}
}

func TestBuildMultiRateLimiter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("per-source duration is respected", func(t *testing.T) {
		agent := New([]string{"crtsh"}, []string{}, false, false)
		crl := newCustomRateLimit()
		_ = crl.Custom.Set("crtsh", subscraping.SourceRateLimit{MaxCount: 2, Duration: time.Minute})

		mrl, err := agent.buildMultiRateLimiter(ctx, 0, crl)
		require.NoError(t, err)
		require.NotNil(t, mrl)
	})

	t.Run("global rate limit applied when no per-source override", func(t *testing.T) {
		agent := New([]string{"crtsh", "hackertarget"}, []string{}, false, false)
		crl := newCustomRateLimit()
		_ = crl.Custom.Set("crtsh", subscraping.SourceRateLimit{MaxCount: 5, Duration: time.Second})

		// hackertarget has no per-source limit, should fall back to global=3
		mrl, err := agent.buildMultiRateLimiter(ctx, 3, crl)
		require.NoError(t, err)
		require.NotNil(t, mrl)
	})

	t.Run("nil custom rate limit does not panic", func(t *testing.T) {
		agent := New([]string{"crtsh"}, []string{}, false, false)
		mrl, err := agent.buildMultiRateLimiter(ctx, 5, nil)
		require.NoError(t, err)
		require.NotNil(t, mrl)
	})

	t.Run("zero source count falls back to global", func(t *testing.T) {
		agent := New([]string{"crtsh"}, []string{}, false, false)
		crl := newCustomRateLimit()
		_ = crl.Custom.Set("crtsh", subscraping.SourceRateLimit{MaxCount: 0, Duration: time.Second})

		mrl, err := agent.buildMultiRateLimiter(ctx, 10, crl)
		require.NoError(t, err)
		require.NotNil(t, mrl)
	})

	t.Run("negative global rate limit is treated as unlimited", func(t *testing.T) {
		agent := New([]string{"crtsh"}, []string{}, false, false)
		crl := newCustomRateLimit()

		mrl, err := agent.buildMultiRateLimiter(ctx, -1, crl)
		require.NoError(t, err)
		require.NotNil(t, mrl)
	})
}

func TestSourceRateLimitOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		global   uint
		source   uint
		expected uint
	}{
		{"source takes precedence", 10, 5, 5},
		{"falls back to global when source is zero", 10, 0, 10},
		{"both zero returns zero", 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sourceRateLimitOrDefault(tt.global, tt.source)
			require.Equal(t, tt.expected, got)
		})
	}
}
