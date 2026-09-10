package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithAdjacentDomainBoundaries(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("check(sub1.example.com)and[sub2.example.com];end")
	results := extractor.Extract(body)

	assert.Contains(t, results, "sub1.example.com")
	assert.Contains(t, results, "sub2.example.com")
}
