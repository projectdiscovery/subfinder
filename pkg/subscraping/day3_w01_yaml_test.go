package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithYAMLFrontmatter(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("---\nhosts:\n  - api-v1.example.com\n  - api-v2.example.com\n---\n")
	results := extractor.Extract(body)

	assert.Contains(t, results, "api-v1.example.com")
	assert.Contains(t, results, "api-v2.example.com")
}
