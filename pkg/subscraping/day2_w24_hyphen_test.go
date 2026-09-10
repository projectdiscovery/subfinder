package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithHyphenatedSubdomainLabels(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("us-east-1.internal-api.example.com and staging-edge-cdn.example.com")
	results := extractor.Extract(body)

	assert.Contains(t, results, "us-east-1.internal-api.example.com")
	assert.Contains(t, results, "staging-edge-cdn.example.com")
}
