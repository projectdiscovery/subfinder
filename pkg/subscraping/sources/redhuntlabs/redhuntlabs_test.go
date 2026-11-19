package redhuntlabs

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type testTransport struct{ target *url.URL }

func (tr testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = tr.target.Scheme
	req.URL.Host = tr.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func TestRunDoesNotFetchFirstPageTwice(t *testing.T) {
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		if _, err := fmt.Fprintf(w, `{"subdomains":["page%s.example.com"],"metadata":{"result_count":1001}}`, page); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	limiter, err := ratelimit.NewMultiLimiter(context.Background(), &ratelimit.Options{
		Key: "redhuntlabs", MaxCount: math.MaxInt32, Duration: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer limiter.Stop()

	ctx := context.WithValue(context.Background(), subscraping.CtxSourceArg, "redhuntlabs")
	for _, tc := range []struct {
		maxResults int
		wantPages  []string
	}{
		{0, []string{"1", "2"}},
		{1, []string{"1"}},
	} {
		pages = nil
		source := &Source{}
		source.AddApiKeys([]string{"https://example.test:test-key"})
		session := &subscraping.Session{
			Client: &http.Client{Transport: testTransport{target}}, MultiRateLimiter: limiter, MaxResults: tc.maxResults,
		}
		for range source.Run(ctx, "example.com", session) {
		}
		if !reflect.DeepEqual(pages, tc.wantPages) {
			t.Errorf("maxResults=%d: requested pages %v, want %v", tc.maxResults, pages, tc.wantPages)
		}
	}
}
