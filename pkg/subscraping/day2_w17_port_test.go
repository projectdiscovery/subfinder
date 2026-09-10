package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithTrailingPortFilter(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`Host: admin.example.com:8443 and api.example.com:443`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "admin.example.com")
	assert.Contains(t, results, "api.example.com")
}
