package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithPostmanCollectionItems(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
{
  "info": { "name": "API Suite" },
  "item": [
    {
      "name": "Auth",
      "request": {
        "url": {
          "raw": "https://identity-gateway.iam.example.com/oauth/token",
          "host": ["identity-gateway", "iam", "example", "com"]
        }
      }
    }
  ]
}
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "identity-gateway.iam.example.com")
}
