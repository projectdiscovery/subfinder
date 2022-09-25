package alienvault_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/alienvault"
	"github.com/stretchr/testify/assert"
)

func TestAlientVault(t *testing.T) {
	var tests = []struct {
		name     string
		domain   string
		timeout  int
		expected subscraping.Result
	}{
		{"TestWithActualDomain", "projectdiscovery.io", 10, subscraping.Result{Type: subscraping.Subdomain, Source: "alienvault", Value: "projectdiscovery.io", Error: nil}},
		{"TestWithEmptyDomain", "", 10, subscraping.Result{Type: subscraping.Error, Source: "alienvault", Value: "", Error: errors.New("")}},
	}

	for _, test := range tests {

		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			session, err := subscraping.NewSession(test.domain, "", 0, test.timeout)
			if err != nil {
				t.Fatalf("Expected nil got %v while creating session\n", err)
			}

			alienvault := alienvault.Source{}
			result := <-alienvault.Run(ctx, test.domain, session)

			assert.Equal(t, test.expected.Type, result.Type)
			assert.Equal(t, test.expected.Source, result.Source)
			assert.Equal(t, reflect.TypeOf(test.expected.Error), reflect.TypeOf(result.Error))
			assert.Contains(t, result.Value, test.expected.Value)
		})
	}
}
