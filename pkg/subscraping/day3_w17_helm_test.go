package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithHelmChartValues(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
global:
  domain: cluster.example.com
ingress:
  hosts:
    - host: helm-app.prod.example.com
      paths: ["/"]
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "cluster.example.com")
	assert.Contains(t, results, "helm-app.prod.example.com")
}
