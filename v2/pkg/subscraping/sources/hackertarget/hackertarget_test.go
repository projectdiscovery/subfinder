package hackertarget_test

import (
	"context"
	"net/url"
	"reflect"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hackertarget"
	"github.com/stretchr/testify/assert"
)

func TestHackerTarget(t *testing.T) {
	var tests = []struct {
		name     string
		domain   string
		timeout  int
		expected subscraping.Result
	}{
		{"TestWithActualDomain", "projectdiscovery.io", 10, subscraping.Result{Type: subscraping.Subdomain, Source: "hackertarget", Value: "projectdiscovery.io", Error: nil}},
		{"TestWithShortTimeout", "projectdiscovery.io", 1, subscraping.Result{Type: subscraping.Error, Source: "hackertarget", Value: "", Error: &url.Error{}}},
		{"TestWithEmptyDomain", "", 10, subscraping.Result{Type: subscraping.Subdomain, Source: "", Value: "", Error: nil}},
	}

	for _, test := range tests {

		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			session, err := subscraping.NewSession(test.domain, "", 0, test.timeout)
			if err != nil {
				t.Fatalf("Expected nil got %v while creating session\n", err)
			}

			hackertarget := hackertarget.Source{}
			result := <-hackertarget.Run(ctx, test.domain, session)

			assert.Equal(t, test.expected.Type, result.Type)
			assert.Equal(t, test.expected.Source, result.Source)
			assert.Equal(t, reflect.TypeOf(test.expected.Error), reflect.TypeOf(result.Error))
			assert.Contains(t, result.Value, test.expected.Value)
		})
	}
}
