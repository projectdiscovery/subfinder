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
	require.Equal(t, []string{"_dmarc.example.com", "legit.example.com", "www.example.com"}, lines)
}

func TestIsValidHostname(t *testing.T) {
	for _, s := range []string{"example.com", "a.b-c.example.com", "_srv._tcp.example.com", "xn--mnchen-3ya.example.com", "1.2.3.4"} {
		require.True(t, isValidHostname(s), s)
	}
	for _, s := range []string{"", "a..b", ".a.b", "a b.c", "a\nb.c", "a\x1b.c", "a/b.c", "a*.b", "A.b", strings.Repeat("a", 64) + ".b", strings.Repeat("a.", 127) + "aa"} {
		require.False(t, isValidHostname(s), "%q", s)
	}
}
