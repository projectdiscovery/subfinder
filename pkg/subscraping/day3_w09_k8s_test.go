package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractWithK8sIngressTLSDefinitions(t *testing.T) {
	extractor, err := NewSubdomainExtractor("example.com")
	assert.Nil(t, err)

	body := strings.NewReader(`
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: prod-ingress
spec:
  tls:
  - hosts:
    - secure-gateway.example.com
    - ingress-lb.example.com
    secretName: prod-tls-cert
`)
	results := extractor.Extract(body)

	assert.Contains(t, results, "secure-gateway.example.com")
	assert.Contains(t, results, "ingress-lb.example.com")
}
