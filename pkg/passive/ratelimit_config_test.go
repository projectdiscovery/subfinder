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

type testSource struct {
	name string
}

func (t *testSource) Run(context.Context, string, *subscraping.Session) <-chan subscraping.Result {
	ch := make(chan subscraping.Result)
	close(ch)
	return ch
}

func (t *testSource) Name() string {
	return t.name
}

func (t *testSource) IsDefault() bool {
	return true
}

func (t *testSource) HasRecursiveSupport() bool {
	return false
}

func (t *testSource) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

func (t *testSource) NeedsKey() bool {
	return false
}

func (t *testSource) AddApiKeys([]string) {}

func (t *testSource) Statistics() subscraping.Statistics {
	return subscraping.Statistics{}
}

func TestBuildRateLimits(t *testing.T) {
	agent := &Agent{
		sources: []subscraping.Source{
			&testSource{name: "github"},
			&testSource{name: "customsource"},
		},
	}

	customRateLimits := &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, subscraping.RateLimit]{
			Map: map[string]subscraping.RateLimit{
				"github": {MaxCount: 2, Duration: time.Minute},
			},
		},
	}

	limits := agent.buildRateLimits(10, customRateLimits)
	require.Equal(t, subscraping.RateLimit{MaxCount: 2, Duration: time.Minute}, limits["github"])
	require.Equal(t, subscraping.RateLimit{MaxCount: 10, Duration: time.Second}, limits["customsource"])

	limits = agent.buildRateLimits(0, customRateLimits)
	require.Equal(t, subscraping.RateLimit{MaxCount: 2, Duration: time.Minute}, limits["github"])
	require.Equal(t, subscraping.RateLimit{MaxCount: math.MaxUint32, Duration: time.Millisecond}, limits["customsource"])
}
