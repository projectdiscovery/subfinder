package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithGraphQLSchemaEndpoints(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
{
  "data": {
    "__schema": {
      "directives": [
        { "name": "federation", "description": "Federated endpoint: https://graphql-gateway.prod.example.com/graphql" },
        { "name": "analytics", "description": "Metrics endpoint: https://telemetry-sink.corp.example.com/v1" }
      ]
    }
  }
}
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "graphql-gateway.prod.example.com")
	assert.Contains(t, results, "telemetry-sink.corp.example.com")
}
