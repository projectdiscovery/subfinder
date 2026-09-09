package runner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type providerSource struct {
	delayedSource
	keys     []string
	observed []string
}

func (*providerSource) Name() string                               { return "testprovider" }
func (*providerSource) KeyRequirement() subscraping.KeyRequirement { return subscraping.RequiredKey }
func (*providerSource) NeedsKey() bool                             { return true }
func (s *providerSource) AddApiKeys(keys []string)                 { s.keys = slices.Clone(keys) }
func (s *providerSource) Run(_ context.Context, domain string, _ *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result, 1)
	defer close(results)
	s.observed = append(s.observed, s.keys...)
	results <- subscraping.Result{Source: s.Name(), Value: "www." + domain}
	return results
}

func TestRunnerProviderSnapshot(t *testing.T) {
	source := &providerSource{}
	old, exists := passive.NameSourceMap[source.Name()]
	passive.NameSourceMap[source.Name()] = source
	t.Cleanup(func() {
		if exists {
			passive.NameSourceMap[source.Name()] = old
		} else {
			delete(passive.NameSourceMap, source.Name())
		}
	})
	t.Setenv("TESTPROVIDER_API_KEY", "")
	file := filepath.Join(t.TempDir(), "providers.yaml")
	if err := os.WriteFile(file, []byte("testprovider:\n  - file-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	options := &Options{Sources: []string{source.Name()}, ProviderConfig: file, Threads: 4, Timeout: 1, MaxEnumerationTime: 1}
	first, err := NewRunner(options)
	if err != nil {
		t.Fatal(err)
	}
	options.Sources[0] = "chaos"
	if err := os.WriteFile(file, []byte("testprovider:\n  - changed-file-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TESTPROVIDER_API_KEY", "environment-key")
	second, err := NewRunner(&Options{Sources: []string{source.Name()}, ProviderConfig: file, Threads: 4, Timeout: 1, MaxEnumerationTime: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TESTPROVIDER_API_KEY", "later-environment-key")
	for _, runner := range []*Runner{first, second, first} {
		if err := runner.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader("example.com\n"), nil); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(source.observed, []string{"file-key", "environment-key", "file-key"}) {
		t.Fatalf("provider snapshots/precedence changed: %v", source.observed)
	}
}
