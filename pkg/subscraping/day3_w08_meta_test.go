package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithHTMLMetaTags(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
<!DOCTYPE html>
<html>
<head>
  <meta property="og:url" content="https://auth.example.com/login" />
  <meta name="twitter:domain" content="portal.example.com" />
</head>
</html>
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "auth.example.com")
	assert.Contains(t, results, "portal.example.com")
}
