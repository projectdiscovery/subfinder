package subscraping

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMaxResponseBodySize int64 = 64 * 1024 // 64KB — small enough for fast tests

// trackedBody records whether Close was called, so we can prove the size cap
// wrapper still closes the underlying body (no connection/body leak).
type trackedBody struct {
	io.Reader
	closed bool
}

func (t *trackedBody) Close() error {
	t.closed = true
	return nil
}

// TestLimitResponseBody_CapsOversizedBody verifies the central cap truncates a
// body larger than maxSize while still delegating Close to the original body.
func TestLimitResponseBody_CapsOversizedBody(t *testing.T) {
	orig := &trackedBody{Reader: newInfiniteReader()}
	resp := &http.Response{Body: orig}

	LimitResponseBody(resp, testMaxResponseBodySize)

	// Reading everything from the (now capped) body must stop at the limit
	// rather than streaming forever.
	n, err := io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	assert.Equal(t, testMaxResponseBodySize, n, "body must be truncated to the cap")

	require.NoError(t, resp.Body.Close())
	assert.True(t, orig.closed, "Close must propagate to the original body (no leak)")
}

// TestLimitResponseBody_SmallBodyUntouched verifies that a legitimate small
// body is passed through unchanged when a cap is set.
func TestLimitResponseBody_SmallBodyUntouched(t *testing.T) {
	const payload = "sub1.example.com\nsub2.example.com\n"
	orig := &trackedBody{Reader: newStringReader(payload)}
	resp := &http.Response{Body: orig}

	LimitResponseBody(resp, testMaxResponseBodySize)

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, string(data))

	require.NoError(t, resp.Body.Close())
	assert.True(t, orig.closed)
}

// TestLimitResponseBody_ZeroIsUnlimited verifies that maxSize <= 0 leaves the
// body uncapped (default product behavior).
func TestLimitResponseBody_ZeroIsUnlimited(t *testing.T) {
	const payload = "sub1.example.com\n"
	orig := &trackedBody{Reader: newStringReader(payload)}
	resp := &http.Response{Body: orig}

	LimitResponseBody(resp, 0)

	// Body must be the original closer (not wrapped).
	require.Equal(t, orig, resp.Body)

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, string(data))
}

// TestLimitResponseBody_NilSafe verifies the helper tolerates a nil response or
// nil body without panicking.
func TestLimitResponseBody_NilSafe(t *testing.T) {
	assert.NotPanics(t, func() { LimitResponseBody(nil, testMaxResponseBodySize) })
	assert.NotPanics(t, func() { LimitResponseBody(&http.Response{}, testMaxResponseBodySize) })
}

// TestHTTPRequestWrapper_CapsResponseBody exercises the full session path
// (client.Do -> httpRequestWrapper) and proves the returned response body is
// bounded when a positive limit is configured.
func TestHTTPRequestWrapper_CapsResponseBody(t *testing.T) {
	const overflow = 4096
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 1024)
		remaining := int(testMaxResponseBodySize) + overflow
		for remaining > 0 {
			chunk := len(buf)
			if remaining < chunk {
				chunk = remaining
			}
			nw, werr := w.Write(buf[:chunk])
			if werr != nil {
				return
			}
			remaining -= nw
		}
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := httpRequestWrapper(server.Client(), req, testMaxResponseBodySize)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	n, err := io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	assert.Equal(t, testMaxResponseBodySize, n, "wrapper must cap the body when limit is set")
}

// TestHTTPRequestWrapper_UnlimitedByDefault verifies that a zero limit leaves
// the body readable beyond any artificial small cap.
func TestHTTPRequestWrapper_UnlimitedByDefault(t *testing.T) {
	const bodySize = 8 * 1024
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, bodySize))
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := httpRequestWrapper(server.Client(), req, 0)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	n, err := io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	assert.Equal(t, int64(bodySize), n, "wrapper must not cap the body when limit is 0")
}

// --- small helpers (avoid pulling in strings/bytes just for the readers) ---

type infiniteReader struct{}

func (infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func newInfiniteReader() io.Reader { return infiniteReader{} }

func newStringReader(s string) io.Reader { return &stringReader{data: s} }

type stringReader struct {
	data string
	pos  int
}

func (s *stringReader) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.pos:])
	s.pos += n
	return n, nil
}
