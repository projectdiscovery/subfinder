package passive

import (
	"context"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

func TestSourcesWithKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	domain := "hackerone.com"
	timeout := 60

	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	ctxParent := context.Background()
	var multiRateLimiter *ratelimit.MultiLimiter
	for _, source := range AllSources {
		if !source.NeedsKey() {
			continue
		}
		multiRateLimiter, _ = addRateLimiter(ctxParent, multiRateLimiter, source.Name(), math.MaxInt32, time.Millisecond)
	}

	session, err := subscraping.NewSession(domain, "", multiRateLimiter, timeout)
	assert.Nil(t, err)

	var expected = subscraping.Result{Type: subscraping.Subdomain, Value: domain, Error: nil}

	for _, source := range AllSources {
		if !source.NeedsKey() {
			continue
		}

		var apiKey string
		if source.Name() == "chaos" {
			apiKey = os.Getenv("PDCP_API_KEY")
		} else {
			apiKey = os.Getenv(fmt.Sprintf("%s_API_KEY", strings.ToUpper(source.Name())))
		}
		if apiKey == "" {
			fmt.Printf("Skipping %s as no API key is provided\n", source.Name())
			continue
		}
		source.AddApiKeys([]string{apiKey})

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
