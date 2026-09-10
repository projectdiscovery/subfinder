package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithXMLCDATASections(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("<data><![CDATA[core-hub.example.com and sync.example.com]]></data>")
	results := extractor.Extract(body)

	assert.Contains(t, results, "core-hub.example.com")
	assert.Contains(t, results, "sync.example.com")
}
