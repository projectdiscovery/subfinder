package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithEnvironmentVariableExports(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("export API_URL=\"https://internal-api.example.com\"\nexport CDN_URL=\"https://assets-cdn.example.com\"")
	results := extractor.Extract(body)

	assert.Contains(t, results, "internal-api.example.com")
	assert.Contains(t, results, "assets-cdn.example.com")
}
