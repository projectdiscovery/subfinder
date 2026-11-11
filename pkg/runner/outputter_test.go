package runner

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/require"
)

// wildcardSource reports one name from a wildcard certificate and one plain name.
type wildcardSource struct{}

func (s *wildcardSource) Run(ctx context.Context, domain string, _ *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)
		for _, v := range []string{"*.wild." + domain, "plain." + domain} {
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Type: subscraping.Subdomain, Source: s.Name(), Value: v}:
			}
		}
	}()
	return results
}
func (*wildcardSource) Name() string                               { return "test-wildcard" }
func (*wildcardSource) IsDefault() bool                            { return false }
func (*wildcardSource) HasRecursiveSupport() bool                  { return true }
func (*wildcardSource) NeedsKey() bool                             { return false }
func (*wildcardSource) KeyRequirement() subscraping.KeyRequirement { return subscraping.NoKey }
func (*wildcardSource) AddApiKeys([]string)                        {}
func (*wildcardSource) Statistics() subscraping.Statistics         { return subscraping.Statistics{} }

// wildcard_certificate is set in JSON output with and without -cs.
func TestJSONWildcardCertificateWithCollectSources(t *testing.T) {
	src := &wildcardSource{}
	previous, hadPrevious := passive.NameSourceMap[src.Name()]
	passive.NameSourceMap[src.Name()] = src
	t.Cleanup(func() {
		if hadPrevious {
			passive.NameSourceMap[src.Name()] = previous
		} else {
			delete(passive.NameSourceMap, src.Name())
		}
	})
	for _, cs := range []bool{false, true} {
		r := &Runner{
			options:      &Options{Threads: 1, Timeout: 1, MaxEnumerationTime: 1, JSON: true, CaptureSources: cs},
			passiveAgent: passive.New([]string{src.Name()}, nil, false, false),
		}
		var out strings.Builder
		_, err := r.EnumerateSingleDomain("example.com", []io.Writer{&out})
		require.NoError(t, err)
		got := map[string]bool{}
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var rec struct {
				Host string `json:"host"`
				WC   bool   `json:"wildcard_certificate"`
			}
			require.NoError(t, json.Unmarshal([]byte(line), &rec))
			got[rec.Host] = rec.WC
		}
		require.True(t, got["wild.example.com"], "-cs=%v: wild.example.com must carry wildcard_certificate", cs)
		val, ok := got["plain.example.com"]
		require.True(t, ok, "-cs=%v: plain.example.com must be present in output", cs)
		require.False(t, val, "-cs=%v: plain.example.com must not carry wildcard_certificate", cs)
	}
}
