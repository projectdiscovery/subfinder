package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithNestedJSONObjects(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("{\"config\":{\"dns\":{\"primary\":\"ns1.prod.example.com\",\"secondary\":\"ns2.prod.example.com\"}}}")
	results := extractor.Extract(body)

	assert.Contains(t, results, "ns1.prod.example.com")
	assert.Contains(t, results, "ns2.prod.example.com")
}
