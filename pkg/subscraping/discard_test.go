package subscraping

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// failingBody reads a little, then errors, and records whether it was closed.
type failingBody struct {
	read   int
	closed bool
}

func (b *failingBody) Read(p []byte) (int, error) {
	b.read++
	if b.read > 1 {
		return 0, errors.New("mock read failure")
	}
	n := copy(p, "partial")
	return n, nil
}

func (b *failingBody) Close() error {
	b.closed = true
	return nil
}

// DiscardHTTPResponse has to close the body whether or not draining it works.
// Every source reaches it through a defer on the error path, so returning early
// on a drain error leaked the connection in exactly the case the helper is there
// to handle.
func TestDiscardHTTPResponseClosesOnDrainError(t *testing.T) {
	body := &failingBody{}
	session := &Session{}
	session.DiscardHTTPResponse(&http.Response{StatusCode: http.StatusTooManyRequests, Body: body})

	if !body.closed {
		t.Error("body was not closed after the drain failed: the connection cannot be reused")
	}
}

// The ordinary path still closes, and a nil response is still a no-op.
func TestDiscardHTTPResponseClosesOnSuccess(t *testing.T) {
	body := &trackingBody{Reader: strings.NewReader("ok")}
	session := &Session{}
	session.DiscardHTTPResponse(&http.Response{StatusCode: http.StatusOK, Body: body})

	if !body.closed {
		t.Error("body was not closed after a successful drain")
	}

	session.DiscardHTTPResponse(nil)
}

type trackingBody struct {
	*strings.Reader
	closed bool
}

func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}
