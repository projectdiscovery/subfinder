package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithCommaSeparatedValues(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("id,subdomain,status\n1,auth.example.com,active\n2,gateway.example.com,inactive")
	results := extractor.Extract(body)

	assert.Contains(t, results, "auth.example.com")
	assert.Contains(t, results, "gateway.example.com")
}
