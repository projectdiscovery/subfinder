package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithEmbeddedURLParameters(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("https://tracker.net/pixel?redirect=https%3A%2F%2Fclick.example.com%2Fpath")
	results := extractor.Extract(body)

	assert.Contains(t, results, "click.example.com")
}
