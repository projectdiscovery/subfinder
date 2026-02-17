package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRateLimitFlagsParsing(t *testing.T) {
	options := &Options{}
	flagSet := newFlagSet(options)

	err := flagSet.CommandLine.Parse([]string{"-rl", "5", "-rls", "github=2/m"})
	require.NoError(t, err)

	require.Equal(t, 5, options.RateLimit)
	rateLimits := options.RateLimits.AsMap()
	require.Contains(t, rateLimits, "github")
	require.Equal(t, uint(2), rateLimits["github"].MaxCount)
	require.Equal(t, time.Minute, rateLimits["github"].Duration)
}
