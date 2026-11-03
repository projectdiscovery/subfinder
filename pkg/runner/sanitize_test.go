package runner

import (
	"context"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/require"
)

// valuesSource returns fixed values, as a misbehaving source could.
type valuesSource struct{ values []string }

func (s *valuesSource) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)
		for _, v := range s.values {
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Type: subscraping.Subdomain, Source: s.Name(), Value: v}:
			}
		}
	}()
	return results
}
func (*valuesSource) Name() string                               { return "test-values" }
func (*valuesSource) IsDefault() bool                            { return false }
func (*valuesSource) HasRecursiveSupport() bool                  { return false }
func (*valuesSource) NeedsKey() bool                             { return false }
func (*valuesSource) KeyRequirement() subscraping.KeyRequirement { return subscraping.NoKey }
func (*valuesSource) AddApiKeys([]string)                        {}
func (*valuesSource) Statistics() subscraping.Statistics         { return subscraping.Statistics{} }

func TestEnumerateDropsInvalidSourceValues(t *testing.T) {
	source := &valuesSource{values: []string{
		"legit.example.com",
		"WWW.Example.com.",
		"_dmarc.example.com",
		"out-of-scope.net\nwww.example.com",
		"out-of-scope.net\r\nwww.example.com",
		"\u001b[2J\u001b[1;31mFAKE-BANNER\u001b[0m.example.com",
		"other.net www.example.com",
		"other.net\twww.example.com",
		"a,b.example.com",
		"a..example.com",
		"bad\x00.example.com",
		"ünicode.example.com",
		strings.Repeat("a", 64) + ".example.com",
		"a/b.example.com",
		"https://url.example.com/path",
		"https://dot.example.com./path",
		"https://query.example.com?x=1",
		"https://frag.example.com#top",
		"two-dots.example.com..",
		"https://url-dots.example.com..",
		"https://port.example.com:8443?x=1",
		"http://bad-port.example.com:x",
	}}
	name := source.Name()
	passive.NameSourceMap[name] = source
	t.Cleanup(func() { delete(passive.NameSourceMap, name) })

	r := &Runner{
		options:         &Options{Threads: 1, Timeout: 1, MaxEnumerationTime: 1},
		passiveAgent:    passive.New([]string{name}, nil, false, false),
		newPassiveAgent: func() *passive.Agent { return passive.New([]string{name}, nil, false, false) },
	}
	var output strings.Builder
	err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader("example.com\n"), []io.Writer{&output})
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	sort.Strings(lines)
	require.Equal(t, []string{"_dmarc.example.com", "dot.example.com", "frag.example.com", "legit.example.com", "port.example.com", "query.example.com", "url.example.com", "www.example.com"}, lines)
}
