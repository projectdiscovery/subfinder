package bufferover

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"testing"
)

func TestRun_Success(t *testing.T) {
	t.Parallel()
	session := &mockSession{body: http.NoBody}
	result := new(Source).Run(context.TODO(), "", session)
	<-result
}

func TestRun_NormalGetErrorNotPanic(t *testing.T) {
	t.Parallel()
	session := &mockSession{err: io.EOF}
	result := new(Source).Run(context.TODO(), "", session)
	<-result
}

func TestRun_ReadErrorNotPanic(t *testing.T) {
	t.Parallel()
	session := &mockSession{body: mockBody{readErr: io.ErrClosedPipe}}
	result := new(Source).Run(context.TODO(), "", session)
	<-result
}

func TestRun_CloseErrorNotPanic(t *testing.T) {
	t.Parallel()
	session := &mockSession{body: mockBody{readErr: io.EOF, closeErr: io.ErrClosedPipe}}
	result := new(Source).Run(context.TODO(), "", session)
	<-result
}

type mockSession struct {
	err  error
	body io.ReadCloser
}

func (s mockSession) NormalGet(url string) (*http.Response, error) {
	return &http.Response{Body: s.body}, s.err
}

func (s mockSession) GetExtractor() *regexp.Regexp {
	return regexp.MustCompile("")
}

type mockBody struct {
	readErr  error
	closeErr error
}

func (b mockBody) Read(p []byte) (n int, err error) { return 0, b.readErr }
func (b mockBody) Close() error                     { return b.closeErr }
