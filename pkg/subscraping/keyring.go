package subscraping

import (
	"math/rand"
	"net/http"
	"sync"
)

// KeyRing hands out the API keys of one source run. It starts at a random key
// to spread load, and moves to the next key when a response shows the current
// one was rejected (401, 403) or is out of quota (429).
type KeyRing[T any] struct {
	mu      sync.Mutex
	keys    []T
	current int
}

// NewKeyRing returns a ring over keys, starting at a random one. Empty
// entries are dropped: a configured blank key is not a key to send.
func NewKeyRing[T any](keys []T) *KeyRing[T] {
	kept := make([]T, 0, len(keys))
	for _, key := range keys {
		if s, isString := any(key).(string); isString && s == "" {
			continue
		}
		kept = append(kept, key)
	}
	ring := &KeyRing[T]{keys: kept}
	if len(kept) > 0 {
		ring.current = rand.Intn(len(kept))
	}
	return ring
}

// Empty reports whether the ring holds no keys.
func (r *KeyRing[T]) Empty() bool {
	return len(r.keys) == 0
}

// Key returns the current key, or the zero value when the ring is empty.
func (r *KeyRing[T]) Key() T {
	r.mu.Lock()
	defer r.mu.Unlock()
	var key T
	if len(r.keys) > 0 {
		key = r.keys[r.current]
	}
	return key
}

// Do sends request with the current key. While the response rejects the key,
// it discards that response and retries with the next one, trying each key at
// most once. The key that worked stays current, so later pages reuse it.
// An empty ring sends one request with the zero key, for sources whose key is
// optional.
func (r *KeyRing[T]) Do(session *Session, request func(key T) (*http.Response, error)) (*http.Response, error) {
	if r.Empty() {
		var zero T
		return request(zero)
	}
	r.mu.Lock()
	start := r.current
	r.mu.Unlock()
	// used is this call's own position in the ring. Other calls can move the
	// shared current key, but they cannot make this call repeat or skip a key.
	used := start
	for attempt := 1; ; attempt++ {
		resp, err := request(r.keys[used])
		if err == nil || resp == nil || !keyRejected(resp.StatusCode) || attempt == len(r.keys) {
			if used != start {
				// The key that worked stays current, so later pages reuse it.
				r.mu.Lock()
				r.current = used
				r.mu.Unlock()
			}
			return resp, err
		}
		session.DiscardHTTPResponse(resp)
		previous := used
		used = (used + 1) % len(r.keys)
		r.mu.Lock()
		// Advance the shared key only if nobody has moved it since this call
		// started, so concurrent rejections do not skip a key.
		if r.current == previous {
			r.current = used
		}
		r.mu.Unlock()
	}
}

func keyRejected(statusCode int) bool {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return true
	}
	return false
}
