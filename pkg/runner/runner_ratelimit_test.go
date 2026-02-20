package runner

import (
	"testing"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/stretchr/testify/require"
)

func TestBuildCustomRateLimit(t *testing.T) {
	customRateLimit := buildCustomRateLimit(map[string]goflags.RateLimit{
		"sitedossier": {
			MaxCount: 2,
			Duration: time.Minute,
		},
		"GitHub": {
			MaxCount: 30,
			Duration: 0,
		},
		"invalid": {
			MaxCount: 0,
			Duration: time.Minute,
		},
	})

	sitedossierRateLimit, ok := customRateLimit.Custom.Get("sitedossier")
	require.True(t, ok)
	require.Equal(t, uint(2), sitedossierRateLimit.MaxCount)
	require.Equal(t, time.Minute, sitedossierRateLimit.Duration)

	githubRateLimit, ok := customRateLimit.Custom.Get("github")
	require.True(t, ok)
	require.Equal(t, uint(30), githubRateLimit.MaxCount)
	require.Equal(t, time.Second, githubRateLimit.Duration)

	_, ok = customRateLimit.Custom.Get("invalid")
	require.False(t, ok)
}
