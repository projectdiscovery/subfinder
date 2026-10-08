package subscraping

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

func newConnectionTestSession(tb testing.TB) (*Session, context.Context) {
	tb.Helper()
	ctx := context.WithValue(tb.Context(), CtxSourceArg, "test")
	limiter, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{Key: "test", IsUnlimited: true})
	require.NoError(tb, err)
	session, err := NewSession("example.com", "", limiter, 5)
	if err != nil {
		limiter.Stop()
	}
	require.NoError(tb, err)
	tb.Cleanup(session.Close)
	return session, ctx
}

// BenchmarkSessionConnectionReuse includes connection establishment in the first
// request and measures successive page requests through the same session.
func BenchmarkSessionConnectionReuse(b *testing.B) {
	for _, protocol := range []string{"HTTP", "HTTPS"} {
		b.Run(protocol, func(b *testing.B) {
			var connections atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "a.example.com\n")
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			if protocol == "HTTPS" {
				server.StartTLS()
			} else {
				server.Start()
			}
			b.Cleanup(server.Close)
			session, ctx := newConnectionTestSession(b)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				response, err := session.SimpleGet(ctx, server.URL)
				if err != nil {
					b.Fatal(err)
				}
				session.DiscardHTTPResponse(response)
			}
			b.StopTimer()
			b.ReportMetric(float64(connections.Load())/float64(b.N), "connections/op")
		})
	}
}

func TestSessionConnectionReuse(t *testing.T) {
	for _, protocol := range []string{"HTTP", "HTTPS"} {
		for _, explicitClose := range []bool{false, true} {
			name := protocol + "/default"
			if explicitClose {
				name = protocol + "/explicit-close"
			}
			t.Run(name, func(t *testing.T) {
				var connections atomic.Int64
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = io.WriteString(w, "a.example.com\n")
				}))
				server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateNew {
						connections.Add(1)
					}
				}
				if protocol == "HTTPS" {
					server.StartTLS()
				} else {
					server.Start()
				}
				t.Cleanup(server.Close)
				session, ctx := newConnectionTestSession(t)
				var headers map[string]string
				if explicitClose {
					headers = map[string]string{"Connection": "close"}
				}
				const requests = 3
				for range requests {
					response, err := session.Get(ctx, server.URL, "", headers)
					require.NoError(t, err)
					body, err := io.ReadAll(response.Body)
					session.DiscardHTTPResponse(response)
					require.NoError(t, err)
					require.Equal(t, "a.example.com\n", string(body))
				}
				wantConnections := int64(1)
				if explicitClose {
					wantConnections = requests
				}
				require.Equal(t, wantConnections, connections.Load())
			})
		}
	}
}

func TestSessionIdleConnectionLifecycle(t *testing.T) {
	closed := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "a.example.com\n")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			close(closed)
		}
	}
	server.Start()
	t.Cleanup(server.Close)
	session, ctx := newConnectionTestSession(t)
	transport := session.Client.Transport.(*http.Transport)
	require.Positive(t, transport.IdleConnTimeout, "unused pooled connections must expire")

	response, err := session.SimpleGet(ctx, server.URL)
	require.NoError(t, err)
	session.DiscardHTTPResponse(response)
	session.Close()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("session close did not release its idle connection")
	}
}
