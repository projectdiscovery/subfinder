package sources_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/alienvault"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/anubis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bevigil"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bufferover"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/builtwith"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/c99"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/censys"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/certspotter"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/chaos"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/chinaz"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/commoncrawl"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/crtname"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/crtsh"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/digitalyama"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/digitorus"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdb"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdumpster"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsrepo"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/domainsproject"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/driftnet"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fofa"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fullhunt"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/github"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/gitlab"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hackertarget"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hudsonrock"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/intelx"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/leakix"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/merklemap"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/netlas"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/onyphe"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/profundis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/pugrecon"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/quake"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rapiddns"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/reconcloud"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/reconeer"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/redhuntlabs"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/riddler"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/robtex"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rsecloud"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/scanmalware"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/securitytrails"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/shodan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/shodanct"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/sitedossier"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/submd"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/thc"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatbook"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatcrowd"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatminer"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/urlscan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/virustotal"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/waybackarchive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/whoisxmlapi"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/windvane"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/zoomeyeapi"
)

// TestSourceConcurrentRuns compares shared-instance runs with an isolated run of
// the same source. Failed requests exercise accounting without provider payloads.
func TestSourceConcurrentRuns(t *testing.T) {
	for _, source := range concurrencySources() {
		t.Run(source.Name(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			source.AddApiKeys(concurrencyKeys(source.Name()))

			blocked, entered, release := blockRequests(ctx, failingTransport)
			defer release()
			// Chaos ignores Session.Client, but puts the domain in its request path.
			mockChaosClient(t, source, transportFunc(func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, "/blocked.example/") {
					return blocked.RoundTrip(req)
				}
				return failingTransport.RoundTrip(req)
			}))

			want := awaitRun(t, ctx, startRun(t, ctx, source, "control.example", failingTransport, 0))
			if want.errors == 0 || len(want.values) != 0 || want.stats.Errors != want.errors || want.stats.Skipped {
				t.Fatalf("mock failure did not exercise the source: %+v", want)
			}

			first := startRun(t, ctx, source, "blocked.example", blocked, 0)
			awaitRequest(t, ctx, entered)
			// Starting another run must not replace the last completed snapshot.
			if got := completedStats(source); got != want.stats {
				t.Errorf("unfinished run changed statistics: got %+v, want %+v", got, want.stats)
			}
			second := awaitRun(t, ctx, startRun(t, ctx, source, "other.example", failingTransport, 0))
			checkOutcome(t, second, want)
			release()
			checkOutcome(t, awaitRun(t, ctx, first), want)
		})
	}
}

// Run, Statistics, and AddApiKeys may be called concurrently on one source.
// The race detector checks the accesses that an ordered overlap cannot expose.
func TestSourceConcurrentAccess(t *testing.T) {
	for _, source := range concurrencySources() {
		t.Run(source.Name(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			mockChaosClient(t, source, failingTransport)
			source.AddApiKeys(concurrencyKeys(source.Name()))
			ctx = context.WithValue(ctx, subscraping.CtxSourceArg, source.Name())
			start := make(chan struct{})
			var workers sync.WaitGroup
			for range 16 {
				session := concurrencySession(t, "example.com", failingTransport, 0)
				workers.Add(1)
				go func() {
					defer workers.Done()
					<-start
					source.AddApiKeys(concurrencyKeys(source.Name()))
					for range source.Run(ctx, "example.com", session) {
						_ = source.Statistics()
					}
					_ = source.Statistics()
				}()
			}
			close(start)
			done := make(chan struct{})
			go func() { workers.Wait(); close(done) }()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("concurrent source calls did not finish")
			}
		})
	}
}

// Successful responses also check the original result-counter regression:
// completing a second run must not truncate the first run's result budget.
func TestSourceConcurrentResults(t *testing.T) {
	cases := []struct {
		source   subscraping.Source
		body     string
		requests int
		limited  bool
	}{
		{&anubis.Source{}, `["one.example.com","two.example.com","three.example.com"]`, 1, false},
		{&bufferover.Source{}, `{"Results":["one.example.com","two.example.com","three.example.com"]}`, 1, false},
		{&censys.Source{}, `{"result":{"hits":[{"certificate_v1":{"resource":{"names":["one.example.com","two.example.com","three.example.com"]}}}]}}`, 1, true},
		{&crtname.Source{}, "one.example.com\ntwo.example.com\nthree.example.com\n", 1, true},
		{&driftnet.Source{}, `{"summary":{"values":{"one.example.com":1,"two.example.com":1,"three.example.com":1}}}`, 4, false},
		{&merklemap.Source{}, `{"count":3,"results":[{"hostname":"one.example.com"},{"hostname":"two.example.com"},{"hostname":"three.example.com"}]}`, 1, true},
		{&shodan.Source{}, `{"domain":"example.com","subdomains":["one","two","three"]}`, 1, true},
		{&sitedossier.Source{}, "one.example.com two.example.com three.example.com", 1, false},
		{&submd.Source{}, "one.example.com\ntwo.example.com\nthree.example.com\n", 1, false},
		{&urlscan.Source{}, `{"results":[{"task":{"domain":"one.example.com"}},{"task":{"domain":"two.example.com"}},{"task":{"domain":"three.example.com"}}]}`, 1, true},
		{&virustotal.Source{}, `{"data":[{"id":"one.example.com"},{"id":"two.example.com"},{"id":"three.example.com"}]}`, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.source.Name(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tc.source.AddApiKeys(concurrencyKeys(tc.source.Name()))
			response := func(domain string) http.RoundTripper {
				return transportFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(strings.ReplaceAll(tc.body, "example.com", domain))),
					}, nil
				})
			}
			firstLimit, secondLimit := 0, 0
			if tc.limited {
				firstLimit, secondLimit = 2, 1
			}
			blocked, entered, release := blockRequests(ctx, response("blocked.example"))
			defer release()
			first := startRun(t, ctx, tc.source, "blocked.example", blocked, firstLimit)
			awaitRequest(t, ctx, entered)
			second := awaitRun(t, ctx, startRun(t, ctx, tc.source, "other.example", response("other.example"), secondLimit))
			expected := func(domain string, limit int) runOutcome {
				values := []string{"one." + domain, "two." + domain, "three." + domain}
				if limit > 0 {
					values = values[:limit]
				}
				slices.Sort(values)
				return runOutcome{values: values, stats: subscraping.Statistics{Requests: tc.requests, Results: len(values)}}
			}
			checkOutcome(t, second, expected("other.example", secondLimit))
			release()
			checkOutcome(t, awaitRun(t, ctx, first), expected("blocked.example", firstLimit))
		})
	}
}

// Worker counters belong to one run, and worker errors must not prevent completion.
func TestSourceConcurrentWorkers(t *testing.T) {
	for _, source := range []subscraping.Source{&github.Source{}, &gitlab.Source{}} {
		t.Run(source.Name(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			source.AddApiKeys(concurrencyKeys(source.Name()))
			response := func(domain string, failFiles bool) http.RoundTripper {
				return transportFunc(func(req *http.Request) (*http.Response, error) {
					body := "one." + domain + " two." + domain + " three." + domain
					switch req.URL.Path {
					case "/search/code":
						body = `{"items":[{"html_url":"https://github.com/mock/repo/blob/main/one"},{"html_url":"https://github.com/mock/repo/blob/main/two"}]}`
					case "/api/v4/search":
						body = `[{"project_id":1,"path":"one","ref":"main"},{"project_id":1,"path":"two","ref":"main"}]`
					default:
						if failFiles {
							return nil, errors.New("mock file failure")
						}
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
				})
			}
			blocked, entered, release := blockRequests(ctx, response("blocked.example", false))
			defer release()
			first := startRun(t, ctx, source, "blocked.example", blocked, 0)
			awaitRequest(t, ctx, entered)
			second := awaitRun(t, ctx, startRun(t, ctx, source, "other.example", response("other.example", false), 0))
			expected := func(domain string) runOutcome {
				return runOutcome{
					values: []string{"one." + domain, "one." + domain, "three." + domain, "three." + domain, "two." + domain, "two." + domain},
					stats:  subscraping.Statistics{Requests: 3, Results: 6},
				}
			}
			checkOutcome(t, second, expected("other.example"))
			release()
			checkOutcome(t, awaitRun(t, ctx, first), expected("blocked.example"))

			failed := awaitRun(t, ctx, startRun(t, ctx, source, "example.com", response("example.com", true), 0))
			wantErrors := 2
			if source.Name() == "github" {
				wantErrors = 1 // GitHub reports the first worker error after joining all workers.
			}
			checkOutcome(t, failed, runOutcome{errors: wantErrors, stats: subscraping.Statistics{Requests: 3, Errors: wantErrors}})
		})
	}
}

func TestSourceConcurrencyCoverage(t *testing.T) {
	covered := make(map[string]bool)
	for _, source := range concurrencySources() {
		if covered[source.Name()] {
			t.Errorf("duplicate source %q", source.Name())
		}
		covered[source.Name()] = true
	}
	for _, source := range passive.AllSources {
		if !covered[source.Name()] {
			t.Errorf("registered source %q has no concurrency test", source.Name())
		}
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "testdata" && !covered[entry.Name()] {
			t.Errorf("source directory %q has no concurrency test", entry.Name())
		}
	}
}

type runOutcome struct {
	values []string
	errors int
	stats  subscraping.Statistics
}

func startRun(t *testing.T, ctx context.Context, source subscraping.Source, domain string, transport http.RoundTripper, limit int) <-chan runOutcome {
	t.Helper()
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, source.Name())
	results := source.Run(ctx, domain, concurrencySession(t, domain, transport, limit))
	done := make(chan runOutcome, 1)
	go func() {
		var outcome runOutcome
		for result := range results {
			if result.Source != source.Name() {
				t.Errorf("result source = %q, want %q", result.Source, source.Name())
			}
			switch result.Type {
			case subscraping.Error:
				outcome.errors++
				if result.Error == nil {
					t.Error("error result has no error")
				}
			case subscraping.Subdomain:
				outcome.values = append(outcome.values, result.Value)
			default:
				t.Errorf("unexpected result type: %v", result.Type)
			}
		}
		slices.Sort(outcome.values)
		outcome.stats = completedStats(source)
		done <- outcome
	}()
	return done
}

func concurrencySession(t *testing.T, domain string, transport http.RoundTripper, limit int) *subscraping.Session {
	t.Helper()
	extractor, err := subscraping.NewSubdomainExtractor(domain)
	if err != nil {
		t.Fatal(err)
	}
	return &subscraping.Session{
		Client:         &http.Client{Transport: transport},
		RequestLimiter: immediateLimiter{},
		Extractor:      extractor,
		MaxResults:     limit,
		// crt.sh must fail its SQL dial before any network access, then use the mock HTTP client.
		Timeout: -1,
	}
}

func awaitRun(t *testing.T, ctx context.Context, done <-chan runOutcome) runOutcome {
	t.Helper()
	select {
	case outcome := <-done:
		return outcome
	case <-ctx.Done():
		t.Fatal("source did not close its result channel")
	}
	return runOutcome{}
}

func checkOutcome(t *testing.T, got, want runOutcome) {
	t.Helper()
	if !slices.Equal(got.values, want.values) || got.errors != want.errors || got.stats != want.stats {
		t.Errorf("run outcome = %+v, want %+v", got, want)
	}
}

func completedStats(source subscraping.Source) subscraping.Statistics {
	stats := source.Statistics()
	stats.TimeTaken = 0 // Duration is not deterministic; all accounting fields are compared.
	return stats
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

var failingTransport = transportFunc(func(*http.Request) (*http.Response, error) {
	return nil, errors.New("mock request failure")
})

type immediateLimiter struct{}

func (immediateLimiter) Wait(ctx context.Context, _ string) error { return ctx.Err() }

func blockRequests(ctx context.Context, next http.RoundTripper) (http.RoundTripper, <-chan struct{}, func()) {
	entered, released := make(chan struct{}), make(chan struct{})
	signal := sync.OnceFunc(func() { close(entered) })
	release := sync.OnceFunc(func() { close(released) })
	transport := transportFunc(func(req *http.Request) (*http.Response, error) {
		signal()
		select {
		case <-released:
			return next.RoundTrip(req)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	return transport, entered, release
}

func awaitRequest(t *testing.T, ctx context.Context, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("source did not reach the mock transport")
	}
}

func concurrencyKeys(name string) []string {
	if name == "redhuntlabs" {
		return []string{"https://mock.example:test-key"}
	}
	// A valid pair also works as an opaque token for sources that do not split keys.
	return []string{"mock.example:test-key"}
}

func mockChaosClient(t *testing.T, source subscraping.Source, transport http.RoundTripper) {
	t.Helper()
	if source.Name() != "chaos" {
		return
	}
	// Keep these tests sequential: the SDK reads shared options when it creates clients.
	previous := retryablehttp.DefaultOptionsSingle
	retryablehttp.DefaultOptionsSingle.WrapTransport = func(http.RoundTripper) http.RoundTripper { return transport }
	retryablehttp.DefaultOptionsSingle.RetryMax = 0
	retryablehttp.DefaultOptionsSingle.Timeout = 5 * time.Second
	t.Cleanup(func() { retryablehttp.DefaultOptionsSingle = previous })
}

// Include inactive implementations: callers can still instantiate them directly.
func concurrencySources() []subscraping.Source {
	return []subscraping.Source{
		&alienvault.Source{},
		&anubis.Source{},
		&bevigil.Source{},
		&bufferover.Source{},
		&builtwith.Source{},
		&c99.Source{},
		&censys.Source{},
		&certspotter.Source{},
		&chaos.Source{},
		&chinaz.Source{},
		&commoncrawl.Source{},
		&crtname.Source{},
		&crtsh.Source{},
		&digitalyama.Source{},
		&digitorus.Source{},
		&dnsdb.Source{},
		&dnsdumpster.Source{},
		&dnsrepo.Source{},
		&domainsproject.Source{},
		&driftnet.Source{},
		&fofa.Source{},
		&fullhunt.Source{},
		&github.Source{},
		&gitlab.Source{},
		&hackertarget.Source{},
		&hudsonrock.Source{},
		&intelx.Source{},
		&leakix.Source{},
		&merklemap.Source{},
		&netlas.Source{},
		&onyphe.Source{},
		&profundis.Source{},
		&pugrecon.Source{},
		&quake.Source{},
		&rapiddns.Source{},
		&reconcloud.Source{},
		&reconeer.Source{},
		&redhuntlabs.Source{},
		&riddler.Source{},
		&robtex.Source{},
		&rsecloud.Source{},
		&scanmalware.Source{},
		&securitytrails.Source{},
		&shodan.Source{},
		&shodanct.Source{},
		&sitedossier.Source{},
		&submd.Source{},
		&thc.Source{},
		&threatbook.Source{},
		&threatcrowd.Source{},
		&threatminer.Source{},
		&urlscan.Source{},
		&virustotal.Source{},
		&waybackarchive.Source{},
		&whoisxmlapi.Source{},
		&windvane.Source{},
		&zoomeyeapi.Source{},
	}
}
