package passive

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

func TestNewWithProviderConfigIsolation(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "environment-key")
	keys := map[string][]string{"shodan": {"first-key"}}
	first := NewWithProviderConfig([]string{"shodan"}, nil, false, false, keys)
	keys["shodan"][0] = "second-key"
	second := NewWithProviderConfig([]string{"shodan"}, nil, false, false, keys)
	keys["shodan"][0] = "changed"
	if first.sources[0] == second.sources[0] || first.sources[0] == NameSourceMap["shodan"] {
		t.Fatal("source instances are shared")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	limiter := testRateLimiter(t, first, 0, nil)
	arrived := make(chan string, 2)
	release := make(chan struct{})
	transport := sourceRoundTripper(func(req *http.Request) (*http.Response, error) {
		arrived <- req.URL.Query().Get("key")
		select {
		case <-release:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		domain := strings.TrimPrefix(req.URL.Path, "/dns/domain/")
		subdomains := `["one"]`
		if domain == "second.example" {
			subdomains = `["one","two"]`
		}
		body := fmt.Sprintf(`{"domain":%q,"subdomains":%s}`, domain, subdomains)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	channels := make([]<-chan subscraping.Result, 0, 2)
	for i, agent := range []*Agent{first, second} {
		domain := []string{"first.example", "second.example"}[i]
		session, err := subscraping.NewSession(domain, "", nil, 1)
		if err != nil {
			t.Fatal(err)
		}
		session.Client.Transport = transport
		session.RequestLimiter = limiter
		t.Cleanup(session.Close)
		channels = append(channels, agent.sources[0].Run(context.WithValue(ctx, subscraping.CtxSourceArg, "shodan"), domain, session))
	}
	var observedKeys []string
	for range 2 {
		select {
		case key := <-arrived:
			observedKeys = append(observedKeys, key)
		case <-ctx.Done():
			t.Fatal("both sources did not enter the HTTP transport concurrently")
		}
	}
	close(release)
	slices.Sort(observedKeys)
	if !slices.Equal(observedKeys, []string{"first-key", "second-key"}) {
		t.Fatal("requests did not retain independently configured keys")
	}
	for i, channel := range channels {
		var values []string
		for result := range channel {
			if result.Type == subscraping.Error {
				t.Fatal(result.Error)
			}
			values = append(values, result.Value)
		}
		want := [][]string{{"one.first.example"}, {"one.second.example", "two.second.example"}}[i]
		if !slices.Equal(values, want) {
			t.Fatalf("source %d results: %v, want %v", i, values, want)
		}
		stats := []*Agent{first, second}[i].GetStatistics()["shodan"]
		if stats.Requests != 1 || stats.Results != len(want) || stats.Errors != 0 || stats.Skipped {
			t.Fatalf("source %d statistics: %+v", i, stats)
		}
	}
}

type sourceRoundTripper func(*http.Request) (*http.Response, error)

func (f sourceRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNewWithProviderConfigSelection(t *testing.T) {
	for _, recursive := range []bool{false, true} {
		legacy := New(nil, []string{"chaos"}, true, recursive)
		fresh := NewWithProviderConfig(nil, []string{"chaos"}, true, recursive, nil)
		if len(legacy.sources) != len(fresh.sources) {
			t.Fatalf("source counts differ: %d != %d", len(legacy.sources), len(fresh.sources))
		}
		for _, source := range fresh.sources {
			if source.Name() == "chaos" || (recursive && !source.HasRecursiveSupport()) {
				t.Fatalf("unexpected source %s", source.Name())
			}
			if source == NameSourceMap[source.Name()] {
				t.Fatalf("shared source %s", source.Name())
			}
		}
	}
	legacy := New([]string{"chaos"}, nil, false, false)
	if legacy.sources[0] != NameSourceMap["chaos"] {
		t.Fatal("legacy constructor no longer uses registered source")
	}
}

func TestEnumerationBorrowsRateLimiter(t *testing.T) {
	agent := &Agent{sources: []subscraping.Source{&blockingSource{exited: make(chan struct{})}}}
	limiter := testRateLimiter(t, agent, 1, nil)
	for range agent.EnumerateSubdomains("example.com", "", 100, 1, time.Second, WithRateLimiter(limiter)) {
	}
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := limiter.Wait(context.Background(), "mock"); err != nil {
			t.Fatal(err)
		}
	}
	// Three tokens must still span two refill intervals after enumeration ends.
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond {
		t.Fatalf("borrowed limiter no longer enforces its budget: %s", elapsed)
	}
}
