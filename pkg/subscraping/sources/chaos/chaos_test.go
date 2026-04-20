package chaos

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeSubdomain(t *testing.T) {
	tests := []struct {
		name      string
		subdomain string
		domain    string
		expected  string
	}{
  {
   name:      "subdomain equals domain - apex returned as-is",
   subdomain: "hotmail.com",
   domain:    "hotmail.com",
   expected:  "hotmail.com",
  },
		{
		 name:      "subdomain part only",
			subdomain: "mail",
			domain:    "hotmail.com",
			expected:  "mail.hotmail.com",
		},
		{
			name:      "full subdomain - upstream returns domain twice #1778",
			subdomain: "mail.hotmail.com",
			domain:    "hotmail.com",
			expected:  "mail.hotmail.com",
		},
		{
			name:      "nested subdomain with domain already present",
			subdomain: "api.mail.hotmail.com",
			domain:    "hotmail.com",
			expected:  "api.mail.hotmail.com",
		},
		{
			name:      "subdomain with dot but not ending with domain",
			subdomain: "api.mail",
			domain:    "hotmail.com",
			expected:  "api.mail.hotmail.com",
		},
		{
			name:      "single char subdomain",
			subdomain: "a",
			domain:    "hotmail.com",
			expected:  "a.hotmail.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeSubdomain(tt.subdomain, tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChaosSource_Metadata(t *testing.T) {
	source := &Source{}

	assert.Equal(t, "chaos", source.Name())
	assert.True(t, source.IsDefault())
	assert.False(t, source.HasRecursiveSupport())
	assert.True(t, source.NeedsKey())
}
