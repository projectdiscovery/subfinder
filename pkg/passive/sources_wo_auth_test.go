package passive

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

func TestSourcesWithoutKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	ignoredSources := []string{
		"commoncrawl",    // commoncrawl is under resourced and will likely time-out so step over it for this test https://groups.google.com/u/2/g/common-crawl/c/3QmQjFA_3y4/m/vTbhGqIBBQAJ
		"riddler",        // failing due to cloudfront protection
		"crtsh",          // Fails in GH Action (possibly IP-based ban) causing a timeout.
		"hackertarget",   // Fails in GH Action (possibly IP-based ban) but works locally
		"waybackarchive", // Fails randomly
		"alienvault",     // 503 Service Temporarily Unavailable
		"digitorus",      // failing with "Failed to retrieve certificate"
		"dnsdumpster",    // failing with "unexpected status code 403 received"
		"anubis",         // failing with "too many redirects"
		"threatcrowd",    // failing with "randomly failing with unmarshal error when hit multiple times"
		"leakix",         // now requires API key (returns 401)
		"reconeer",       // now requires API key (returns 401)
		"sitedossier",    // flaky - returns no results in CI
	}

	domain := "hackerone.com"
	timeout := 60

	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	ctxParent := context.Background()

	var multiRateLimiter *ratelimit.MultiLimiter
	for _, source := range AllSources {
		if source.NeedsKey() || slices.Contains(ignoredSources, source.Name()) {
			continue
		}
		multiRateLimiter, _ = addRateLimiter(ctxParent, multiRateLimiter, source.Name(), math.MaxInt32, time.Millisecond)
	}

	session, err := subscraping.NewSession(domain, "", multiRateLimiter, timeout)
	assert.Nil(t, err)

	var expected = subscraping.Result{Type: subscraping.Subdomain, Value: domain, Error: nil}

	for _, source := range AllSources {
		if source.NeedsKey() || slices.Contains(ignoredSources, source.Name()) {
			continue
		}

		t.Run(source.Name(), func(t *testing.T) {
			var results []subscraping.Result

			ctxWithValue := context.WithValue(ctxParent, subscraping.CtxSourceArg, source.Name())
			for result := range source.Run(ctxWithValue, domain, session) {
				results = append(results, result)

				assert.Equal(t, source.Name(), result.Source, "wrong source name")

				if result.Type != subscraping.Error {
					assert.True(t, strings.HasSuffix(strings.ToLower(result.Value), strings.ToLower(expected.Value)),
						fmt.Sprintf("result(%s) is not subdomain of %s", strings.ToLower(result.Value), expected.Value))
				} else {
					assert.Equal(t, reflect.TypeOf(expected.Error), reflect.TypeOf(result.Error), fmt.Sprintf("%s: %s", result.Source, result.Error))
				}
			}

			assert.GreaterOrEqual(t, len(results), 1, fmt.Sprintf("No result found for %s", source.Name()))
		})
	}
}
