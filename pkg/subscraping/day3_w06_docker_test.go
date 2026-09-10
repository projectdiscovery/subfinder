package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithDockerComposeServiceDefinitions(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader("services:\n  web:\n    image: nginx\n    labels:\n      - \"traefik.http.routers.web.rule=Host(\`dashboard.example.com\`)\"")
	results := extractor.Extract(body)

	assert.Contains(t, results, "dashboard.example.com")
}
