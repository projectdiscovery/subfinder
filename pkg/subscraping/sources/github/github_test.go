package github

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/require"
)

// Subdomains in code search results are extracted with the shared extractor:
// a longer host such as example.community or example.com.evil.org is not cut
// down to a subdomain of example.com, and case and one-letter labels match.
func TestGithubExtractsWholeSubdomains(t *testing.T) {
	raw := "https://api.example.community/v1\nfoo.example.com.evil.org\ncdn.example.computer\nnotexample.com\nAPI.EXAMPLE.COM\nx.example.com\nwww.example.com\nDomain=.dotted.example.com\nx\\nfoo.example.com\\tbar\n"
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `{"total_count":1,"items":[{"name":"a","html_url":"https://github.com/o/r/blob/main/a.txt","text_matches":[]}]}`
		if req.URL.Host == "raw.githubusercontent.com" {
			body = raw
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: req}, nil
	})
	extractor, err := subscraping.NewSubdomainExtractor("example.com")
	require.NoError(t, err)
	session := &subscraping.Session{Client: &http.Client{Transport: transport}, RequestLimiter: immediateLimiter{}, Extractor: extractor}

	source := &Source{}
	source.AddApiKeys([]string{"token"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, source.Name())

	var got []string
	for result := range source.Run(ctx, "example.com", session) {
		require.Equal(t, subscraping.Subdomain, result.Type, "%v", result.Error)
		got = append(got, result.Value)
	}
	require.ElementsMatch(t, []string{"api.example.com", "x.example.com", "www.example.com", "dotted.example.com", "foo.example.com"}, got)
}
