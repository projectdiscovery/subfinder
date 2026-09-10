package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithConsulServiceCatalog(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
[
  {
    "Node": "consul-node-1",
    "Address": "10.1.1.1",
    "ServiceID": "payment-api",
    "ServiceName": "payment-service",
    "ServiceAddress": "pay-gateway.prod.example.com",
    "ServicePort": 8443
  }
]
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "pay-gateway.prod.example.com")
}
