package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithSemicolonSeparators(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("server=edge01.example.com;backup=edge02.example.com;ttl=300")
	results := extractor.Extract(body)

	assert.Contains(t, results, "edge01.example.com")
	assert.Contains(t, results, "edge02.example.com")
}
