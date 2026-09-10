package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithSpringBootProperties(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
spring.datasource.url=jdbc:postgresql://db-cluster.infra.example.com:5432/main
eureka.client.serviceUrl.defaultZone=https://discovery-registry.cloud.example.com/eureka/
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "db-cluster.infra.example.com")
	assert.Contains(t, results, "discovery-registry.cloud.example.com")
}
