package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithMarkdownTableLinks(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
| Service | URL |
|---|---|
| Admin | [Admin Portal](https://admin-panel.infra.example.com) |
| Health | [Status Page](https://status-monitor.cloud.example.com) |
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "admin-panel.infra.example.com")
	assert.Contains(t, results, "status-monitor.cloud.example.com")
}
