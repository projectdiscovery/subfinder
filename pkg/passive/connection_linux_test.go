package passive

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/require"
)

// TestEnumerationReleasesConnections guards against descriptor accumulation
// across domains. The child process isolates the descriptor limit from other tests.
func TestEnumerationReleasesConnections(t *testing.T) {
	const childEnv = "SUBFINDER_TEST_ENUMERATION_FD_CHILD"
	if os.Getenv(childEnv) != "1" {
		executable, err := os.Executable()
		require.NoError(t, err)
		cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestEnumerationReleasesConnections$", "-test.timeout=20s")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "descriptor-limited enumeration failed:\n%s", output)
		return
	}

	var limit syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit))
	limit.Cur = min(limit.Cur, 64)
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit))

	var connections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "result\n")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)
	agent := &Agent{sources: []subscraping.Source{&connectionSource{url: server.URL}}}
	const domains = 128
	for i := range domains {
		domain := fmt.Sprintf("domain-%d.example", i)
		var enumerationErr error
		var results int
		for result := range agent.EnumerateSubdomainsWithCtx(t.Context(), domain, "", 0, 2, 5*time.Second) {
			if result.Type == subscraping.Error {
				enumerationErr = result.Error
			} else {
				results++
			}
		}
		require.NoError(t, enumerationErr, "enumerating %s", domain)
		require.Equal(t, 2, results, "enumerating %s", domain)
	}
	require.Equal(t, int64(domains), connections.Load(), "each domain must reuse its connection")
}

type connectionSource struct {
	url string
}

func (s *connectionSource) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)
		for i := range 2 {
			response, err := session.SimpleGet(ctx, s.url)
			session.DiscardHTTPResponse(response)
			if err != nil {
				results <- subscraping.Result{Type: subscraping.Error, Source: s.Name(), Error: err}
				return
			}
			results <- subscraping.Result{Type: subscraping.Subdomain, Source: s.Name(), Value: fmt.Sprintf("host%d.%s", i, domain)}
		}
	}()
	return results
}

func (s *connectionSource) Name() string                       { return "connection-test" }
func (s *connectionSource) IsDefault() bool                    { return false }
func (s *connectionSource) HasRecursiveSupport() bool          { return false }
func (s *connectionSource) NeedsKey() bool                     { return false }
func (s *connectionSource) AddApiKeys(_ []string)              {}
func (s *connectionSource) Statistics() subscraping.Statistics { return subscraping.Statistics{} }
func (s *connectionSource) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}
