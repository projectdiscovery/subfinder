package subscraping

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegexSubdomainExtractor_Extract(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		text   string
		want   []string
	}{
		{
			name:   "simple subdomain",
			domain: "example.com",
			text:   "www.example.com",
			want:   []string{"www.example.com"},
		},
		{
			name:   "multi-level subdomain",
			domain: "example.com",
			text:   "a.b.c.example.com",
			want:   []string{"a.b.c.example.com"},
		},
		{
			name:   "case is normalized to lower",
			domain: "example.com",
			text:   "WWW.Example.COM",
			want:   []string{"www.example.com"},
		},
		{
			name:   "wildcard prefix is preserved",
			domain: "example.com",
			text:   "*.example.com",
			want:   []string{"*.example.com"},
		},
		{
			name:   "multiple subdomains in one blob",
			domain: "example.com",
			text:   "foo.example.com\nbar.example.com",
			want:   []string{"foo.example.com", "bar.example.com"},
		},
		{
			name:   "trailing dot (FQDN form) is kept",
			domain: "example.com",
			text:   "host.example.com.",
			want:   []string{"host.example.com"},
		},
		{
			// The dot in the domain must be literal: "example.com" must not match
			// "exampleXcom". Before escaping the domain, the regex "." matched any
			// character and produced this false positive.
			name:   "domain dots are literal, not wildcards",
			domain: "example.com",
			text:   "sub.exampleXcom",
			want:   nil,
		},
		{
			// A host that merely ends with the target domain but belongs to a
			// different apex must not be reported.
			name:   "domain as a prefix of another apex is rejected",
			domain: "example.com",
			text:   "foo.example.com.evil.org",
			want:   nil,
		},
		{
			name:   "longer label ending in domain is rejected",
			domain: "example.com",
			text:   "notexample.com",
			want:   nil,
		},
		{
			name:   "bracketed and json quoted subdomains",
			domain: "example.com",
			text:   `{"domain":"api.example.com","alt":["test.example.com"]}`,
			want:   []string{"api.example.com", "test.example.com"},
		},
		{
			name:   "subdomains in full URL context",
			domain: "example.com",
			text:   `https://auth.example.com/login?redirect=https://admin.example.com:8080`,
			want:   []string{"auth.example.com", "admin.example.com"},
		},
	}


	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, err := NewSubdomainExtractor(tt.domain)
			require.NoError(t, err)
			got := extractor.Extract(tt.text)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}
