package subscraping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSPFSubdomainExtractionW23(t *testing.T) {
	record := "v=spf1 include:_spf.example.com include:mail.target.com -all"
	parts := strings.Fields(record)
	var includes []string
	for _, p := range parts {
		if strings.HasPrefix(p, "include:") {
			includes = append(includes, strings.TrimPrefix(p, "include:"))
		}
	}
	assert.Equal(t, 2, len(includes))
	assert.Equal(t, "_spf.example.com", includes[0])
}
