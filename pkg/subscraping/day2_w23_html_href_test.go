package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithHTMLAnchorTags(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`<a href="https://docs.example.com/api">Docs</a><a href="//status.example.com">Status</a>`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "docs.example.com")
	assert.Contains(t, results, "status.example.com")
}
