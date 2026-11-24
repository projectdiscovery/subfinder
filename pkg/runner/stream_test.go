package runner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/require"
)

// gatedSource sends its first host, then waits for release before the second,
// so a test can observe output while the enumeration is still running.
type gatedSource struct{ release chan struct{} }

func (s *gatedSource) Run(ctx context.Context, domain string, _ *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)
		results <- subscraping.Result{Type: subscraping.Subdomain, Source: s.Name(), Value: "first." + domain}
		select {
		case <-s.release:
		case <-ctx.Done():
			return
		}
		results <- subscraping.Result{Type: subscraping.Subdomain, Source: s.Name(), Value: "second." + domain}
	}()
	return results
}
func (*gatedSource) Name() string                               { return "test-gated" }
func (*gatedSource) IsDefault() bool                            { return false }
func (*gatedSource) HasRecursiveSupport() bool                  { return false }
func (*gatedSource) NeedsKey() bool                             { return false }
func (*gatedSource) KeyRequirement() subscraping.KeyRequirement { return subscraping.NoKey }
func (*gatedSource) AddApiKeys([]string)                        {}
func (*gatedSource) Statistics() subscraping.Statistics         { return subscraping.Statistics{} }

// notifyWriter signals each write so the test can wait for streamed output.
type notifyWriter struct {
	mu     sync.Mutex
	buf    strings.Builder
	writes chan struct{}
}

func (w *notifyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	select {
	case w.writes <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (w *notifyWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func sortedLines(s string) []string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	sort.Strings(lines)
	return lines
}

func TestPlainOutputStreamsHostsAsFound(t *testing.T) {
	source := &gatedSource{release: make(chan struct{})}
	name := source.Name()
	passive.NameSourceMap[name] = source
	t.Cleanup(func() { delete(passive.NameSourceMap, name) })

	dir := t.TempDir()
	r := &Runner{
		options:         &Options{Threads: 1, Timeout: 5, MaxEnumerationTime: 1, OutputDirectory: dir},
		passiveAgent:    passive.New([]string{name}, nil, false, false),
		newPassiveAgent: func() *passive.Agent { return passive.New([]string{name}, nil, false, false) },
	}
	out := &notifyWriter{writes: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() {
		done <- r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader("example.com\n"), []io.Writer{out})
	}()

	select {
	case <-out.writes:
	case <-time.After(5 * time.Second):
		t.Fatal("first host was not written before the source finished")
	}
	require.Equal(t, "first.example.com\n", out.String())

	close(source.release)
	require.NoError(t, <-done)

	want := []string{"first.example.com", "second.example.com"}
	require.Equal(t, want, sortedLines(out.String()))
	file, err := os.ReadFile(filepath.Join(dir, "example.com.txt"))
	require.NoError(t, err)
	require.Equal(t, want, sortedLines(string(file)))
}
