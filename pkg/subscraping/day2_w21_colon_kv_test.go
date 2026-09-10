package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithColonSeparatedPairs(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("endpoint:auth-api.example.com\nservice:billing-v2.example.com")
	results := extractor.Extract(body)

	assert.Contains(t, results, "auth-api.example.com")
	assert.Contains(t, results, "billing-v2.example.com")
}
