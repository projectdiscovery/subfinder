package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithMarkdownTableColumns(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("| Service | Endpoint |\n| Primary | core.example.com |\n| Secondary | edge.example.com |")
	results := extractor.Extract(body)

	assert.Contains(t, results, "core.example.com")
	assert.Contains(t, results, "edge.example.com")
}
