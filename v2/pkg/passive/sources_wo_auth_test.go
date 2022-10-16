package passive

import (
	"context"
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

		t.Run(source.Name(), func(t *testing.T) {
			var results []subscraping.Result

			for result := range source.Run(ctx, domain, session) {
				results = append(results, result)

				assert.Equal(t, source.Name(), result.Source)

				assert.Equal(t, expected.Type, result.Type)
				assert.Equal(t, reflect.TypeOf(expected.Error), reflect.TypeOf(result.Error), result.Error)

				assert.True(t, strings.HasSuffix(strings.ToLower(result.Value), strings.ToLower(expected.Value)))
			}

			assert.GreaterOrEqual(t, len(results), 1)
		})
	}
}
