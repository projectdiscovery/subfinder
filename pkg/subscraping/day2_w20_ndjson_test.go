package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithNDJSONStream(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("{\"domain\":\"node1.example.com\"}\n{\"domain\":\"node2.example.com\"}\n")
	results := extractor.Extract(body)

	assert.Contains(t, results, "node1.example.com")
	assert.Contains(t, results, "node2.example.com")
}
