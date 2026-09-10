package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithGitLabCIEnvironmentURLs(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
deploy_review:
  stage: deploy
  environment:
    name: review/$CI_COMMIT_REF_SLUG
    url: https://review-app-42.stage.example.com
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "review-app-42.stage.example.com")
}
