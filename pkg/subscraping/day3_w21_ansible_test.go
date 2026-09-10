package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithAnsibleInventoryHosts(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
[webservers]
web-alpha.prod.example.com ansible_host=10.0.1.10
web-beta.prod.example.com ansible_host=10.0.1.11
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "web-alpha.prod.example.com")
	assert.Contains(t, results, "web-beta.prod.example.com")
}
