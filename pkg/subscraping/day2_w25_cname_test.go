package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithCNAMERecords(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("app.example.com CNAME lb-01.prod.example.com.")
	results := extractor.Extract(body)

	assert.Contains(t, results, "app.example.com")
	assert.Contains(t, results, "lb-01.prod.example.com")
}
