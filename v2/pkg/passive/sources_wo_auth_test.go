package passive

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

func TestSourcesWithoutKeys(t *testing.T) {
	domain := "hackerone.com"
	timeout := 60

	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	ctx := context.Background()
	session, err := subscraping.NewSession(domain, "", 0, timeout)
	assert.Nil(t, err)

	var expected = subscraping.Result{Type: subscraping.Subdomain, Value: domain, Error: nil}

	for _, source := range AllSources {
		if source.NeedsKey() {
			continue
		}

		if source.Name() == "commoncrawl" {
			continue // commoncrawl is under resourced and will likely time-out so step over it for this test https://groups.google.com/u/2/g/common-crawl/c/3QmQjFA_3y4/m/vTbhGqIBBQAJ
		}

		t.Run(source.Name(), func(t *testing.T) {
			var results []subscraping.Result

			for result := range source.Run(ctx, domain, session) {
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
