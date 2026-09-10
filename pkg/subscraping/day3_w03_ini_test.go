package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithINIConfigurationSections(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("[server]\nhost = gateway-01.example.com\nbackup_host = gateway-02.example.com\n")
	results := extractor.Extract(body)

	assert.Contains(t, results, "gateway-01.example.com")
	assert.Contains(t, results, "gateway-02.example.com")
}
