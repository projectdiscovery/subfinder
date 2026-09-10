package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithOpenAPIServerDefinitions(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
{
  "openapi": "3.0.0",
  "info": { "title": "Sample API", "version": "1.0.0" },
  "servers": [
    { "url": "https://api-sandbox.example.com/v1" },
    { "url": "https://staging-gateway.example.com/v1" }
  ]
}
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "api-sandbox.example.com")
	assert.Contains(t, results, "staging-gateway.example.com")
}
