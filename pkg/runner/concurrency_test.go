package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// delayedSource models a source waiting on I/O without using an external service.
type delayedSource struct {
	delay     time.Duration
	active    atomic.Int64
	peak      atomic.Int64
	completed atomic.Int64
	takeToken bool
}

func (s *delayedSource) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)
		active := s.active.Add(1)
		defer s.active.Add(-1)
		for peak := s.peak.Load(); active > peak; peak = s.peak.Load() {
			if s.peak.CompareAndSwap(peak, active) {
				break
			}
		}
		if s.takeToken {
			if err := session.RequestLimiter.Wait(ctx, s.Name()); err != nil {
				return
			}
		}
		timer := time.NewTimer(s.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		select {
		case <-ctx.Done():
		case results <- subscraping.Result{Type: subscraping.Subdomain, Source: s.Name(), Value: "www." + domain}:
			s.completed.Add(1)
		}
	}()
	return results
}
func (*delayedSource) Name() string                               { return "benchmark-delay" }
func (*delayedSource) IsDefault() bool                            { return false }
func (*delayedSource) HasRecursiveSupport() bool                  { return true }
func (*delayedSource) NeedsKey() bool                             { return false }
func (*delayedSource) KeyRequirement() subscraping.KeyRequirement { return subscraping.NoKey }
func (*delayedSource) AddApiKeys([]string)                        {}
func (*delayedSource) Statistics() subscraping.Statistics         { return subscraping.Statistics{} }

func delayedRunner(t testing.TB, threads int, source *delayedSource) *Runner {
	t.Helper()
	name := source.Name()
	previous, existed := passive.NameSourceMap[name]
	passive.NameSourceMap[name] = source
	t.Cleanup(func() {
		if existed {
			passive.NameSourceMap[name] = previous
		} else {
			delete(passive.NameSourceMap, name)
		}
	})
	return &Runner{
		options:         &Options{Threads: threads, Timeout: 1, MaxEnumerationTime: 1},
		passiveAgent:    passive.New([]string{name}, nil, false, false),
		newPassiveAgent: func() *passive.Agent { return passive.New([]string{name}, nil, false, false) },
	}
}

// BenchmarkEnumerateMultipleDomains includes session construction, source fan-out,
// result processing and output. Every batch contains 40 domains and each source
// waits 5 ms, so it measures overlapping I/O waits rather than faster parsing.
func BenchmarkEnumerateMultipleDomains(b *testing.B) {
	var input strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&input, "target-%d.example\n", i)
	}
	domains := input.String()
	for _, threads := range []int{1, 4, 10} {
		b.Run(fmt.Sprintf("threads=%d", threads), func(b *testing.B) {
			source := &delayedSource{delay: 5 * time.Millisecond}
			r := delayedRunner(b, threads, source)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader(domains), []io.Writer{io.Discard}); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if got, want := source.completed.Load(), int64(b.N*40); got != want {
				b.Fatalf("completed %d domains, want %d", got, want)
			}
			b.ReportMetric(float64(source.peak.Load()), "peak-domains")
		})
	}
}

func TestEnumerateMultipleDomainsConcurrency(t *testing.T) {
	for _, threads := range []int{1, 4} {
		t.Run(fmt.Sprintf("threads=%d", threads), func(t *testing.T) {
			source := &delayedSource{delay: 10 * time.Millisecond}
			r := delayedRunner(t, threads, source)
			var output strings.Builder
			var input strings.Builder
			for i := 0; i < 12; i++ {
				fmt.Fprintf(&input, "target-%d.example\n", i)
			}
			if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader(input.String()), []io.Writer{&output}); err != nil {
				t.Fatal(err)
			}
			if got := source.peak.Load(); got != int64(threads) {
				t.Errorf("peak domains=%d, want %d", got, threads)
			}
			if got := len(strings.Fields(output.String())); got != 12 {
				t.Errorf("output hosts=%d, want 12", got)
			}
		})
	}
}

func TestEnumerateMultipleDomainsCallbacksAndFiles(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", jsonOutput), func(t *testing.T) {
			source := &delayedSource{delay: time.Millisecond}
			r := delayedRunner(t, 4, source)
			r.options.JSON = jsonOutput
			r.options.CaptureSources = jsonOutput
			r.options.OutputFile = filepath.Join(t.TempDir(), "all.txt")
			var calls []string
			r.options.ResultCallback = func(entry *resolve.HostEntry) { calls = append(calls, entry.Host) }
			var first, second strings.Builder
			input := "one.example\ntwo.example\none.example\nthree.example\n"
			if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader(input), []io.Writer{&first, &second}); err != nil {
				t.Fatal(err)
			}
			saved, err := os.ReadFile(r.options.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			if first.String() != second.String() || first.String() != string(saved) {
				t.Fatal("writers received different domain output")
			}
			if len(calls) != 4 {
				t.Fatalf("callbacks=%d, want 4", len(calls))
			}
			lines := strings.Split(strings.TrimSpace(first.String()), "\n")
			if len(lines) != 4 {
				t.Fatalf("lines=%d, want 4", len(lines))
			}
			if jsonOutput {
				for _, line := range lines {
					var value map[string]any
					if err := json.Unmarshal([]byte(line), &value); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestEnumerateMultipleDomainsDuplicateOutputDirectory(t *testing.T) {
	source := &delayedSource{delay: time.Millisecond}
	r := delayedRunner(t, 4, source)
	r.options.OutputDirectory = t.TempDir()
	if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader(strings.Repeat("same.example\n", 12)), nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(r.options.OutputDirectory, "same.example.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "www.same.example\n" {
		t.Fatalf("corrupted repeated-domain output: %q", data)
	}
}

func TestEnumerateMultipleDomainsSharedRateLimit(t *testing.T) {
	source := &delayedSource{takeToken: true}
	r := delayedRunner(t, 4, source)
	r.rateLimit = &subscraping.CustomRateLimit{
		Custom:         mapsutil.SyncLockMap[string, uint]{Map: map[string]uint{source.Name(): 1}},
		CustomDuration: mapsutil.SyncLockMap[string, time.Duration]{Map: map[string]time.Duration{source.Name(): 40 * time.Millisecond}},
	}
	start := time.Now()
	if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader("a.example\nb.example\nc.example\nd.example\ne.example\nf.example\n"), nil); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 160*time.Millisecond {
		t.Fatalf("workers multiplied provider budget: six tokens in %s", elapsed)
	}
	if got := source.completed.Load(); got != 6 {
		t.Fatalf("completed=%d, want 6", got)
	}
}

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }

type failedReader struct{ err error }

func (r failedReader) Read([]byte) (int, error) { return 0, r.err }

func TestEnumerateMultipleDomainsErrors(t *testing.T) {
	sentinel := errors.New("test I/O failure")
	for _, test := range []struct {
		name   string
		reader io.Reader
		writer io.Writer
	}{
		{"reader", failedReader{sentinel}, io.Discard},
		{"writer", strings.NewReader(strings.Repeat("a.example\n", 40)), failedWriter{sentinel}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &delayedSource{delay: time.Millisecond}
			r := delayedRunner(t, 4, source)
			err := r.EnumerateMultipleDomainsWithCtx(context.Background(), test.reader, []io.Writer{test.writer})
			if !errors.Is(err, sentinel) {
				t.Fatalf("error=%v, want sentinel", err)
			}
			if source.active.Load() != 0 {
				t.Fatal("source still active after return")
			}
		})
	}
}

func TestEnumerateMultipleDomainsCancellation(t *testing.T) {
	source := &delayedSource{delay: time.Second}
	r := delayedRunner(t, 4, source)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := r.EnumerateMultipleDomainsWithCtx(ctx, strings.NewReader(strings.Repeat("a.example\n", 40)), nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v, want deadline exceeded", err)
	}
	if source.active.Load() != 0 {
		t.Fatal("source still active after cancellation")
	}
	if source.completed.Load() != 0 {
		t.Fatal("unexpected completed sources after cancellation")
	}
}

func TestEnumerateMultipleDomainsThreadBounds(t *testing.T) {
	for _, threads := range []int{-1, 0} {
		t.Run(fmt.Sprint(threads), func(t *testing.T) {
			source := &delayedSource{}
			r := delayedRunner(t, threads, source)
			err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader("a.example\nb.example\n"), nil)
			if threads < 0 {
				if err == nil {
					t.Fatal("negative threads accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if source.peak.Load() != 1 {
				t.Fatal("unset SDK threads must use one worker")
			}
		})
	}
}

func TestEnumerateMultipleDomainsOutputPreflight(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprint(directory), func(t *testing.T) {
			blocked := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(blocked, nil, 0600); err != nil {
				t.Fatal(err)
			}
			source := &delayedSource{}
			r := delayedRunner(t, 4, source)
			if directory {
				r.options.OutputDirectory = blocked
			} else {
				r.options.OutputFile = filepath.Join(blocked, "output.txt")
			}
			if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader("one.example\ntwo.example\n"), nil); err == nil {
				t.Fatal("invalid output accepted")
			}
			if source.completed.Load() != 0 {
				t.Fatal("provider work started before output validation")
			}
		})
	}
}
func TestEnumerateMultipleDomainsEmptyInputDoesNotCreateOutput(t *testing.T) {
	source := &delayedSource{}
	r := delayedRunner(t, 4, source)
	r.options.OutputFile = filepath.Join(t.TempDir(), "absent.txt")
	if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader("\n\n"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.options.OutputFile); !os.IsNotExist(err) {
		t.Fatalf("empty input created output: %v", err)
	}
}
