package passive

import (
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

func TestResolveSourceRateLimit(t *testing.T) {
	customRates := &subscraping.CustomRateLimit{
		Custom: *mapsutil.NewSyncLockMap[string, uint](
			mapsutil.WithMap(mapsutil.Map[string, uint]{
				"sitedossier": 2,
				"github":      0,
			}),
		),
	}

	testCases := []struct {
		name            string
		globalRateLimit int
		customRates     *subscraping.CustomRateLimit
		sourceName      string
		expected        uint
	}{
		{
			name:            "uses global rate limit when no custom map is provided",
			globalRateLimit: 5,
			customRates:     nil,
			sourceName:      "sitedossier",
			expected:        5,
		},
		{
			name:            "uses global rate limit when source is not in custom map",
			globalRateLimit: 7,
			customRates:     customRates,
			sourceName:      "shodan",
			expected:        7,
		},
		{
			name:            "uses source specific override when present",
			globalRateLimit: 7,
			customRates:     customRates,
			sourceName:      "sitedossier",
			expected:        2,
		},
		{
			name:            "matches source specific override case insensitively",
			globalRateLimit: 7,
			customRates:     customRates,
			sourceName:      "SiteDossier",
			expected:        2,
		},
		{
			name:            "treats zero custom limit as fallback to global",
			globalRateLimit: 9,
			customRates:     customRates,
			sourceName:      "github",
			expected:        9,
		},
		{
			name:            "stays unlimited when no global or custom rate is configured",
			globalRateLimit: 0,
			customRates:     customRates,
			sourceName:      "waybackarchive",
			expected:        0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := resolveSourceRateLimit(tc.globalRateLimit, tc.customRates, tc.sourceName)
			if actual != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, actual)
			}
		})
	}
}
