package windvane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type unlimitedLimiter struct{}

func (unlimitedLimiter) Wait(ctx context.Context, _ string) error { return ctx.Err() }

func newTestSession(t testing.TB, domain string, transport http.RoundTripper) *subscraping.Session {
	t.Helper()
	extractor, err := subscraping.NewSubdomainExtractor(domain)
	if err != nil {
		t.Fatal(err)
	}
	return &subscraping.Session{
		Client:         &http.Client{Transport: transport},
		Extractor:      extractor,
		RequestLimiter: unlimitedLimiter{},
	}
}

func TestWindvanePagination(t *testing.T) {
	tests := []struct {
		name          string
		total         int
		count         int
		totalPage     int
		expectedPages []int
	}{
		{
			name:          "total 2 with count 1000 requests 1 page (#1979)",
			total:         2,
			count:         1000,
			totalPage:     1,
			expectedPages: []int{1},
		},
		{
			name:          "total 1000 with count 1000 requests 1 page (#1979)",
			total:         1000,
			count:         1000,
			totalPage:     1,
			expectedPages: []int{1},
		},
		{
			name:          "total 1500 with count 1000 requests 2 pages (#1979)",
			total:         1500,
			count:         1000,
			totalPage:     2,
			expectedPages: []int{1, 2},
		},
		{
			name:          "total 1500 with count 1000 and no total_page requests 2 pages (#1979)",
			total:         1500,
			count:         1000,
			totalPage:     0,
			expectedPages: []int{1, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requestedPages []int

			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				var reqData struct {
					PageRequest struct {
						Page  int `json:"page"`
						Count int `json:"count"`
					} `json:"page_request"`
				}
				if err := json.Unmarshal(body, &reqData); err != nil {
					return nil, err
				}

				requestedPages = append(requestedPages, reqData.PageRequest.Page)

				entriesCount := tt.count
				remaining := tt.total - (reqData.PageRequest.Page-1)*tt.count
				if remaining < entriesCount {
					entriesCount = remaining
				}
				if entriesCount < 0 {
					entriesCount = 0
				}

				list := make([]domainEntry, entriesCount)
				for i := 0; i < entriesCount; i++ {
					list[i] = domainEntry{Domain: fmt.Sprintf("sub%d.example.com", (reqData.PageRequest.Page-1)*tt.count+i+1)}
				}

				respObj := response{
					Code: 0,
					Msg:  "success",
					Data: responseData{
						List: list,
						PageResponse: pageInfo{
							Total:     strconv.Itoa(tt.total),
							Count:     strconv.Itoa(tt.count),
							TotalPage: strconv.Itoa(tt.totalPage),
						},
					},
				}
				respBytes, _ := json.Marshal(respObj)

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(respBytes)),
					Header:     make(http.Header),
				}, nil
			})

			src := &Source{
				apiKeys: []string{"test-api-key"},
			}

			session := newTestSession(t, "example.com", transport)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx = context.WithValue(ctx, subscraping.CtxSourceArg, "windvane")

			ch := src.Run(ctx, "example.com", session)
			for range ch {
			}

			if !slices.Equal(requestedPages, tt.expectedPages) {
				t.Fatalf("requested pages %v, expected %v", requestedPages, tt.expectedPages)
			}
		})
	}
}
