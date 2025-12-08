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
	// maxCensysPages is the maximum number of pages to fetch from the API
	maxCensysPages = 10
	// maxPerPage is the maximum number of results per page
	maxPerPage = 100
	// baseURL is the Censys Platform API base URL
	baseURL = "https://api.platform.censys.io"
	// searchEndpoint is the global data search query endpoint
	searchEndpoint = "/v3/global/search/query"
	// queryPrefix is the Censys query language prefix for certificate name search
	queryPrefix = "certificate.names: "
	// authHeaderPrefix is the Bearer token prefix for Authorization header
	authHeaderPrefix = "Bearer "
	// contentTypeJSON is the Content-Type header value for JSON
	contentTypeJSON = "application/json"
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

		// PickRandom selects a random API key from configured keys.
		// This enables load balancing when users configure multiple PATs
		// (e.g., CENSYS_API_KEY=pat1,pat2,pat3) to distribute requests
		// and avoid hitting rate limits on a single key.
		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		apiURL := baseURL + searchEndpoint
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
				Query:    queryPrefix + domain,
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
				apiURL,
				"",
				map[string]string{
					"Content-Type":  contentTypeJSON,
					"Authorization": authHeaderPrefix + randomApiKey,
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
