package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithTerraformProviderConfigs(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
provider "aws" {
  endpoints {
    s3  = "https://s3-gateway.infra.example.com"
    ec2 = "https://ec2-control.cloud.example.com"
  }
}
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "s3-gateway.infra.example.com")
	assert.Contains(t, results, "ec2-control.cloud.example.com")
}
