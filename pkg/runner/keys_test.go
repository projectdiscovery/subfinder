package runner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/require"
)

// keyedSource sends its key in the query string, as many real sources do, and
// skips like they do when the key is malformed.
type keyedSource struct {
	url     string
	mu      sync.Mutex
	key     string
	skipped bool
}

func (s *keyedSource) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)
		s.mu.Lock()
		key := s.key
		s.skipped = key == "malformed"
		s.mu.Unlock()
		if key == "malformed" {
			return
		}
		resp, err := session.SimpleGet(ctx, s.url+"?apikey="+key)
		result := subscraping.Result{Type: subscraping.Subdomain, Source: s.Name(), Value: "www." + domain}
		if err != nil {
			result = subscraping.Result{Type: subscraping.Error, Source: s.Name(), Error: err}
		}
		session.DiscardHTTPResponse(resp)
		results <- result
	}()
	return results
}
func (*keyedSource) Name() string                               { return "test-keyed" }
func (*keyedSource) IsDefault() bool                            { return false }
func (*keyedSource) HasRecursiveSupport() bool                  { return false }
func (*keyedSource) NeedsKey() bool                             { return true }
func (*keyedSource) KeyRequirement() subscraping.KeyRequirement { return subscraping.RequiredKey }
func (s *keyedSource) AddApiKeys(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = keys[0]
}
func (s *keyedSource) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return subscraping.Statistics{Skipped: s.skipped}
}

func TestCheckKeys(t *testing.T) {
	statusByKey := map[string]int{"good": 200, "revoked": 401, "banned": 403, "exhausted": 429, "secret-broken": 500}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusByKey[r.URL.Query().Get("apikey")])
	}))
	defer server.Close()

	source := &keyedSource{url: server.URL}
	name := source.Name()
	passive.NameSourceMap[name] = source
	t.Cleanup(func() { delete(passive.NameSourceMap, name) })

	r := &Runner{
		options: &Options{Timeout: 5, JSON: true, Sources: []string{name}},
		providerKeys: map[string][]string{
			name: {"good", "revoked", "banned", "exhausted", "secret-broken", "malformed"},
		},
	}
	var out strings.Builder
	require.NoError(t, r.CheckKeys(context.Background(), &out))

	var got []KeyCheck
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var check KeyCheck
		require.NoError(t, json.Unmarshal([]byte(line), &check))
		got = append(got, check)
	}
	require.Equal(t, []KeyCheck{
		{Source: name, Key: 1, Status: KeyValid},
		{Source: name, Key: 2, Status: KeyInvalid, Error: "status 401"},
		{Source: name, Key: 3, Status: KeyInvalid, Error: "status 403"},
		{Source: name, Key: 4, Status: KeyRateLimited, Error: "status 429"},
		{Source: name, Key: 5, Status: KeyError, Error: "status 500"},
		{Source: name, Key: 6, Status: KeySkipped},
	}, got)
	require.NotContains(t, out.String(), "secret")
}

func TestRedactKey(t *testing.T) {
	message := `Get "https://api.example/?email=me@example.com&key=s3cr3t": dial tcp: timeout`
	require.Equal(t, `Get "https://api.example/?email=[redacted]&key=[redacted]": dial tcp: timeout`, redactKey(message, "me@example.com:s3cr3t"))
}

// silentSource accepts any key and returns nothing, like a quota body or a
// timeout does. Its key must not be reported as valid.
type silentSource struct{}

func (*silentSource) Run(_ context.Context, _ string, _ *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	close(results)
	return results
}
func (*silentSource) Name() string                               { return "test-silent" }
func (*silentSource) IsDefault() bool                            { return false }
func (*silentSource) HasRecursiveSupport() bool                  { return false }
func (*silentSource) NeedsKey() bool                             { return true }
func (*silentSource) KeyRequirement() subscraping.KeyRequirement { return subscraping.RequiredKey }
func (*silentSource) AddApiKeys([]string)                        {}
func (*silentSource) Statistics() subscraping.Statistics         { return subscraping.Statistics{} }

func TestCheckKeysNoResultIsUnverified(t *testing.T) {
	source := &silentSource{}
	name := source.Name()
	passive.NameSourceMap[name] = source
	t.Cleanup(func() { delete(passive.NameSourceMap, name) })

	r := &Runner{
		options:      &Options{Timeout: 5, JSON: true, Sources: []string{name}},
		providerKeys: map[string][]string{name: {"unconfirmed-key"}},
	}
	var out strings.Builder
	require.NoError(t, r.CheckKeys(context.Background(), &out))
	require.Contains(t, out.String(), `"status":"unverified"`)
	require.NotContains(t, out.String(), `"status":"valid"`)
}

func TestRedactKeyQuotedAndShortParts(t *testing.T) {
	// A key with a newline reaches the error quoted, as \n.
	require.Equal(t, `Get "https://api.example/?k=[redacted]": refused`,
		redactKey(`Get "https://api.example/?k=abc\ndef-secret": refused`, "abc\ndef-secret"))
	// A short part (under minRedactLen) must not mangle unrelated text.
	require.Equal(t, `reason: abx [redacted]`, redactKey("reason: abx verylongsecret", "ab:verylongsecret"))
}

// -check-keys with -o must write the report to the file, not only to stdout.
func TestCheckKeysWritesOutputFile(t *testing.T) {
	source := &silentSource{}
	name := source.Name()
	passive.NameSourceMap[name] = source
	t.Cleanup(func() { delete(passive.NameSourceMap, name) })

	file := filepath.Join(t.TempDir(), "keys.json")
	r := &Runner{
		options: &Options{Timeout: 5, JSON: true, CheckKeys: true, Sources: []string{name},
			OutputFile: file, Output: io.Discard},
		providerKeys: map[string][]string{name: {"unconfirmed-key"}},
	}
	require.NoError(t, r.RunEnumerationWithCtx(context.Background()))
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Contains(t, string(data), `"status":"unverified"`)
}
