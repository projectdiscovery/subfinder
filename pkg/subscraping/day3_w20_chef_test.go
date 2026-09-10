package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithChefCookbookAttributes(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
default['app']['master_node'] = 'chef-master.infra.example.com'
default['app']['repo_url'] = 'https://pkg-repo.prod.example.com/yum'
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "chef-master.infra.example.com")
	assert.Contains(t, results, "pkg-repo.prod.example.com")
}
