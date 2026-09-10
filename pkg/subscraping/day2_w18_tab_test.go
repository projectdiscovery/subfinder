package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithTabSeparators(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("vpn.example.com\t10.0.0.1\t\tmail.example.com\t10.0.0.2")
	results := extractor.Extract(body)

	assert.Contains(t, results, "vpn.example.com")
	assert.Contains(t, results, "mail.example.com")
}
