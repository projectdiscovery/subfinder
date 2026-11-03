package sources_test

import (
	"context"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/builtwith"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdb"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/driftnet"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/gitlab"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/leakix"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/netlas"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/virustotal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequiredKeySources_SkipWithoutKey(t *testing.T) {
	sources := []subscraping.Source{
		&builtwith.Source{},
		&dnsdb.Source{},
		&driftnet.Source{},
		&gitlab.Source{},
		&leakix.Source{},
		&netlas.Source{},
		&virustotal.Source{},
	}

	for _, s := range sources {
		t.Run(s.Name(), func(t *testing.T) {
			require.Equal(t, subscraping.RequiredKey, s.KeyRequirement(), "expected source to require an API key")

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			mrl, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
				Key:         s.Name(),
				IsUnlimited: false,
				MaxCount:    math.MaxInt32,
				Duration:    time.Millisecond,
			})
			require.NoError(t, err)

			session := &subscraping.Session{
				Client:           http.DefaultClient,
				MultiRateLimiter: mrl,
			}
			ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, s.Name())

			var count int
			var errCount int
			for r := range s.Run(ctxWithValue, "example.com", session) {
				if r.Type == subscraping.Error {
					errCount++
				} else {
					count++
				}
			}

			assert.Equal(t, 0, count, "expected 0 results without api key")
			assert.Equal(t, 0, errCount, "expected 0 errors without api key")
			stats := s.Statistics()
			assert.True(t, stats.Skipped, "expected source to mark Statistics.Skipped = true")
			assert.Equal(t, 0, stats.Requests, "expected 0 requests made without api key")
		})
	}
}
