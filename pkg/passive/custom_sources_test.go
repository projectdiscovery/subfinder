package passive

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type registeredSource struct {
	name    string
	keys    []string
	started chan string
	release chan struct{}
	active  atomic.Int32
	maximum atomic.Int32
	stats   subscraping.Statistics
}

func (s *registeredSource) Name() string              { return s.name }
func (s *registeredSource) IsDefault() bool           { return true }
func (s *registeredSource) HasRecursiveSupport() bool { return true }
func (s *registeredSource) NeedsKey() bool            { return true }
func (s *registeredSource) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}
func (s *registeredSource) AddApiKeys(keys []string)           { s.keys = keys }
func (s *registeredSource) Statistics() subscraping.Statistics { return s.stats }
func (s *registeredSource) Run(_ context.Context, domain string, _ *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	active := s.active.Add(1)
	if active > s.maximum.Load() {
		s.maximum.Store(active)
	}
	s.started <- domain
	go func() {
		defer close(results)
		defer s.active.Add(-1)
		<-s.release
		s.stats = subscraping.Statistics{Results: len(domain)}
		results <- subscraping.Result{Value: domain + ":" + s.keys[0]}
	}()
	return results
}

func registerTestSource(t *testing.T, name string) *registeredSource {
	t.Helper()
	old, existed := NameSourceMap[name]
	t.Cleanup(func() {
		if existed {
			NameSourceMap[name] = old
		} else {
			delete(NameSourceMap, name)
		}
	})
	source := &registeredSource{name: name, keys: []string{"preconfigured"}, started: make(chan string, 2), release: make(chan struct{}, 2)}
	NameSourceMap[name] = source
	return source
}

func TestCustomSourceSelectionAndSerialization(t *testing.T) {
	for _, name := range []string{"shodan", "test-custom-source"} {
		t.Run(name, func(t *testing.T) {
			source := registerTestSource(t, name)
			first := NewWithProviderConfig([]string{name}, nil, false, false, nil)
			second := NewWithProviderConfig([]string{name}, nil, false, false, map[string][]string{name: {"second-key"}})
			if _, ok := first.sources[0].(*registeredSource); ok {
				t.Fatal("custom source was not isolated")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			one := first.sources[0].Run(ctx, "one", nil)
			select {
			case <-source.started:
			case <-ctx.Done():
				t.Fatal("custom source override was not used")
			}
			two := second.sources[0].Run(ctx, "second", nil)
			source.release <- struct{}{}
			var values []string
			for result := range one {
				values = append(values, result.Value)
			}
			select {
			case <-source.started:
			case <-ctx.Done():
				t.Fatal("second source did not start")
			}
			source.release <- struct{}{}
			for result := range two {
				values = append(values, result.Value)
			}
			if len(values) != 2 || values[0] != "one:preconfigured" || values[1] != "second:second-key" {
				t.Fatalf("results: %v", values)
			}
			if source.maximum.Load() != 1 {
				t.Fatal("custom source ran concurrently")
			}
			if first.GetStatistics()[name].Results != 3 || second.GetStatistics()[name].Results != 6 {
				t.Fatal("statistics not isolated")
			}
		})
	}
}

func TestCustomSourceCancellationWhileWaiting(t *testing.T) {
	source := registerTestSource(t, "test-custom-cancel")
	first := NewWithProviderConfig([]string{source.name}, nil, false, false, nil)
	second := NewWithProviderConfig([]string{source.name}, nil, false, false, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	one := first.sources[0].Run(ctx, "one", nil)
	select {
	case <-source.started:
	case <-ctx.Done():
		t.Fatal("first source did not start")
	}
	waitCtx, waitCancel := context.WithCancel(ctx)
	two := second.sources[0].Run(waitCtx, "two", nil)
	waitCancel()
	select {
	case _, ok := <-two:
		if ok {
			t.Fatal("canceled waiter emitted a result")
		}
	case <-ctx.Done():
		t.Fatal("canceled waiter blocked")
	}
	source.release <- struct{}{}
	for range one {
	}
	select {
	case <-source.started:
		t.Fatal("canceled source ran")
	default:
	}
}

func TestCustomSourceDrainsAfterCancellation(t *testing.T) {
	source := registerTestSource(t, "test-custom-drain")
	agent := NewWithProviderConfig([]string{source.name}, nil, false, false, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := agent.sources[0].Run(ctx, "one", nil)
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("source did not start")
	}
	cancel()
	source.release <- struct{}{}
	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled enumeration did not drain custom source")
	}
	if source.active.Load() != 0 || agent.GetStatistics()[source.name].Results != 3 {
		t.Fatal("custom source did not finish and preserve statistics")
	}
}

// A custom adapter may use the legacy public Session limiter directly.
type legacyLimiterSource struct{ blockingSource }

func (s *legacyLimiterSource) Run(_ context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result, 1)
	defer close(results)
	if session.MultiRateLimiter == nil {
		results <- subscraping.Result{Type: subscraping.Error}
		return results
	}
	if err := session.MultiRateLimiter.Take(s.Name()); err != nil {
		results <- subscraping.Result{Type: subscraping.Error, Error: err}
		return results
	}
	results <- subscraping.Result{Source: s.Name(), Value: "www." + domain}
	return results
}
func TestCustomSourceLegacySessionLimiter(t *testing.T) {
	source := &legacyLimiterSource{}
	previous, exists := NameSourceMap[source.Name()]
	NameSourceMap[source.Name()] = source
	t.Cleanup(func() {
		if exists {
			NameSourceMap[source.Name()] = previous
		} else {
			delete(NameSourceMap, source.Name())
		}
	})
	agent := NewWithProviderConfig([]string{source.Name()}, nil, false, false, nil)
	count := 0
	for result := range agent.EnumerateSubdomains("example.com", "", 0, 1, time.Second, WithRateLimiter(testRateLimiter(t, agent, 0, nil))) {
		if result.Type == subscraping.Error {
			t.Fatal("custom adapter lost its legacy session limiter")
		}
		count++
	}
	if count != 1 {
		t.Fatalf("results=%d, want 1", count)
	}
}

func TestCustomSourceLegacySharedBudget(t *testing.T) {
	source := &legacyLimiterSource{}
	previous, exists := NameSourceMap[source.Name()]
	NameSourceMap[source.Name()] = source
	t.Cleanup(func() {
		if exists {
			NameSourceMap[source.Name()] = previous
		} else {
			delete(NameSourceMap, source.Name())
		}
	})
	custom := newCustomRateLimit(map[string]uint{source.Name(): 1}, map[string]time.Duration{source.Name(): 40 * time.Millisecond})
	agents := make([]*Agent, 4)
	for i := range agents {
		agents[i] = NewWithProviderConfig([]string{source.Name()}, nil, false, false, nil)
	}
	limiter := testRateLimiter(t, agents[0], 0, custom)
	started := time.Now()
	done := make(chan struct{}, 4)
	for _, agent := range agents {
		go func() {
			for range agent.EnumerateSubdomains("example.com", "", 0, 1, time.Second, WithCustomRateLimit(custom), WithRateLimiter(limiter)) {
			}
			done <- struct{}{}
		}()
	}
	for range agents {
		<-done
	}
	if elapsed := time.Since(started); elapsed < 80*time.Millisecond {
		t.Fatalf("custom source received fresh per-domain bursts: %s", elapsed)
	}
}

func TestCustomSourceUnconfiguredRetainsSharedConfiguration(t *testing.T) {
	source := registerTestSource(t, "test-shared-config")
	inherited := NewWithProviderConfig([]string{source.Name()}, nil, false, false, nil)
	configured := NewWithProviderConfig([]string{source.Name()}, nil, false, false, map[string][]string{source.Name(): {"configured"}})
	// The legacy registry exposes one mutable instance and no key getter. An
	// unconfigured custom source inherits its current configuration, not a snapshot.
	for _, agent := range []*Agent{configured, inherited} {
		source.release <- struct{}{}
		for result := range agent.sources[0].Run(context.Background(), "domain", nil) {
			if result.Value != "domain:configured" {
				t.Fatalf("custom registry configuration changed: %q", result.Value)
			}
		}
	}
}

func TestCustomSourceLegacyLimiterScope(t *testing.T) {
	source := registerTestSource(t, "test-legacy-scope")
	agent := NewWithProviderConfig([]string{source.Name(), "anubis"}, nil, false, false, nil)
	limiter := testRateLimiter(t, agent, 1, nil)
	if _, err := limiter.legacy.GetLimit(source.Name()); err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.legacy.GetLimit("anubis"); err == nil {
		t.Fatal("built-in source has an unused legacy limiter")
	}
}
