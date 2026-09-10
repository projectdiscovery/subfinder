package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithCircleCIConfigOrbs(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
version: 2.1
orbs:
  deploy: circleci/aws-s3@3.0.0
jobs:
  build:
    environment:
      DEPLOY_HOST: "circle-deploy.infra.example.com"
      ARTIFACT_BUCKET: "https://build-artifacts.s3.example.com"
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "circle-deploy.infra.example.com")
	assert.Contains(t, results, "build-artifacts.s3.example.com")
}
