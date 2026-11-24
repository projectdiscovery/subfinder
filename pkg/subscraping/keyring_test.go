package subscraping

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

func keyServer(t *testing.T, statusByKey map[string]int) (*Session, func(key string) (*http.Response, error), func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		mu.Lock()
		seen = append(seen, key)
		mu.Unlock()
		w.WriteHeader(statusByKey[key])
	}))
	t.Cleanup(server.Close)
	ctx := context.WithValue(t.Context(), CtxSourceArg, "test")
	limiter, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{Key: "test", IsUnlimited: true})
	require.NoError(t, err)
	session, err := NewSession("example.com", "", limiter, 5)
	require.NoError(t, err)
	t.Cleanup(session.Close)
	request := func(key string) (*http.Response, error) {
		return session.SimpleGet(ctx, server.URL+"?key="+key)
	}
	return session, request, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestKeyRingMovesPastRejectedKeys(t *testing.T) {
	session, request, seen := keyServer(t, map[string]int{"revoked": 401, "banned": 403, "exhausted": 429, "good": 200})
	ring := NewKeyRing([]string{"revoked", "banned", "exhausted", "good"})

	resp, err := ring.Do(session, request)
	require.NoError(t, err)
	session.DiscardHTTPResponse(resp)
	require.Equal(t, "good", ring.Key())
	require.Equal(t, "good", seen()[len(seen())-1])
	require.LessOrEqual(t, len(seen()), 4)

	// The working key stays current for later pages.
	before := len(seen())
	resp, err = ring.Do(session, request)
	require.NoError(t, err)
	session.DiscardHTTPResponse(resp)
	require.Equal(t, []string{"good"}, seen()[before:])
}

func TestKeyRingTriesEachKeyOnce(t *testing.T) {
	session, request, seen := keyServer(t, map[string]int{"a": 401, "b": 429, "c": 403})
	ring := NewKeyRing([]string{"a", "b", "c"})

	resp, err := ring.Do(session, request)
	require.Error(t, err)
	require.True(t, keyRejected(resp.StatusCode), "the last rejection is returned, got %d", resp.StatusCode)
	session.DiscardHTTPResponse(resp)
	require.ElementsMatch(t, []string{"a", "b", "c"}, seen())
}

func TestKeyRingKeepsOtherErrors(t *testing.T) {
	session, request, seen := keyServer(t, map[string]int{"a": 500, "b": 200})
	ring := NewKeyRing([]string{"a", "b"})
	for ring.Key() != "a" {
		ring = NewKeyRing([]string{"a", "b"})
	}

	resp, err := ring.Do(session, request)
	require.Error(t, err)
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	session.DiscardHTTPResponse(resp)
	require.Equal(t, []string{"a"}, seen())
}

func TestKeyRingEmpty(t *testing.T) {
	ring := NewKeyRing[string](nil)
	require.True(t, ring.Empty())
	require.Equal(t, "", ring.Key())
	var sent []string
	_, err := ring.Do(nil, func(key string) (*http.Response, error) {
		sent = append(sent, key)
		return nil, nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{""}, sent)
}
