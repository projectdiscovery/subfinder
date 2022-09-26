package passive

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
)

func TestSourcesWithoutAuth(t *testing.T) {
	var tests = []struct {
		name     string
		domain   string
		timeout  int
		expected subscraping.Result
	}{
		{"TestWithActualDomain", "hackerone.com", 10, subscraping.Result{Type: subscraping.Subdomain, Source: "", Value: "hackerone.com", Error: nil}},
		{"TestWithEmptyDomain", "", 10, subscraping.Result{Type: subscraping.Error, Source: "", Value: "", Error: errors.New("")}},
	}

	for _, source := range AllSources {
		if source.NeedsKey() {
			continue
		}

		for _, test := range tests {
			t.Run(fmt.Sprintf("%s/%s", source.Name(), test.name), func(t *testing.T) {
				ctx := context.Background()
				session, err := subscraping.NewSession(test.domain, "", 0, test.timeout)
				if err != nil {
					t.Fatalf("Expected nil got %v while creating session\n", err)
				}

				result := <-source.Run(ctx, test.domain, session)

				assert.Equal(t, test.expected.Type, result.Type)
				assert.Equal(t, source.Name(), result.Source)
				assert.Equal(t, reflect.TypeOf(test.expected.Error), reflect.TypeOf(result.Error))
				assert.Contains(t, result.Value, test.expected.Value)
			})
		}
	}

}
