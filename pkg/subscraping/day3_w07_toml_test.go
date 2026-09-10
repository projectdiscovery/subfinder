package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithTOMLConfigurationBlocks(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
[servers.alpha]
ip = "10.0.0.1"
domain = "alpha.corp.example.com"

[servers.beta]
ip = "10.0.0.2"
domain = "beta.corp.example.com"
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "alpha.corp.example.com")
	assert.Contains(t, results, "beta.corp.example.com")
}
