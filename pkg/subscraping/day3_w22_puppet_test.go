package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithPuppetManifestNodes(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
node 'db-primary.infra.example.com' {
  include role::database
}
node 'cache-cluster.prod.example.com' {
  include role::redis
}
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "db-primary.infra.example.com")
	assert.Contains(t, results, "cache-cluster.prod.example.com")
}
