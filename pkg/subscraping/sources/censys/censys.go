// Package censys logic
package censys

import (
	"bytes"
	"context"
	"net/http"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	maxCensysPages = 10
	maxPerPage     = 100
)

// Platform API request body
type searchRequest struct {
	Query    string   `json:"query"`
	Fields   []string `json:"fields,omitempty"`
	PageSize int      `json:"page_size,omitempty"`
	Cursor   string   `json:"cursor,omitempty"`
}

// Platform API response structures
type response struct {
	Result result `json:"result"`
}

type result struct {
	Hits   []hit  `json:"hits"`
	Cursor string `json:"cursor"`
	Total  int64  `json:"total"`
}

type hit struct {
	Certificate certificate `json:"certificate"`
}

type certificate struct {
	Names []string `json:"names"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		searchEndpoint := "https://api.platform.censys.io/v3/global/search/query"
		cursor := ""
		currentPage := 1

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Build request body
			reqBody := searchRequest{
				Query:    "certificate.names: " + domain,
				Fields:   []string{"certificate.names"},
				PageSize: maxPerPage,
			}
			if cursor != "" {
				reqBody.Cursor = cursor
			}

			bodyBytes, err := jsoniter.Marshal(reqBody)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				return
			}

			// Make POST request with Bearer token auth
			resp, err := session.HTTPRequest(
				ctx,
				http.MethodPost,
				searchEndpoint,
				"",
				map[string]string{
					"Content-Type":  "application/json",
					"Authorization": "Bearer " + randomApiKey,
				},
				bytes.NewReader(bodyBytes),
				subscraping.BasicAuth{},
			)

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var censysResponse response
			err = jsoniter.NewDecoder(resp.Body).Decode(&censysResponse)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			session.DiscardHTTPResponse(resp)

			for _, hit := range censysResponse.Result.Hits {
				for _, name := range hit.Certificate.Names {
					select {
					case <-ctx.Done():
						return
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: name}:
						s.results++
					}
				}
			}

			cursor = censysResponse.Result.Cursor
			if cursor == "" || currentPage >= maxCensysPages {
				break
			}
			currentPage++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "censys"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
