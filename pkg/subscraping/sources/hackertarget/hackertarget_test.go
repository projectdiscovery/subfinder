package hackertarget

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rewriteTransport struct {
	target *url.URL
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = r.target.Scheme
	req.URL.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func run(t *testing.T, body string) (subs []string, errs []error) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	require.NoError(t, err)

	extractor, err := subscraping.NewSubdomainExtractor("example.com")
	require.NoError(t, err)
	mrl, err := ratelimit.NewMultiLimiter(context.Background(), &ratelimit.Options{
		Key: "hackertarget", MaxCount: math.MaxInt32, Duration: time.Millisecond,
	})
	require.NoError(t, err)
	session := &subscraping.Session{
		Client:           &http.Client{Transport: &rewriteTransport{target: target}, Timeout: 5 * time.Second},
		MultiRateLimiter: mrl,
		Extractor:        extractor,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, "hackertarget")
	source := &Source{}
	for r := range source.Run(ctx, "example.com", session) {
		switch r.Type {
		case subscraping.Subdomain:
			subs = append(subs, r.Value)
		case subscraping.Error:
			errs = append(errs, r.Error)
		}
	}
	assert.Equal(t, len(errs), source.Statistics().Errors)
	return subs, errs
}

func TestHackertargetParsesResults(t *testing.T) {
	subs, errs := run(t, "www.example.com,1.2.3.4\napi.example.com,5.6.7.8\n")
	assert.Empty(t, errs)
	assert.Equal(t, []string{"www.example.com", "api.example.com"}, subs)
}

// The API reports errors with HTTP 200 and a plain text body.
func TestHackertargetReportsErrorBody(t *testing.T) {
	for _, body := range []string{
		"error invalid key",
		"Error invalid key\n",
		"API count exceeded - Increase Quota with Membership",
	} {
		t.Run(body, func(t *testing.T) {
			subs, errs := run(t, body)
			assert.Empty(t, subs)
			require.Len(t, errs, 1)
			assert.Equal(t, strings.TrimSpace(body), errs[0].Error())
		})
	}
}
