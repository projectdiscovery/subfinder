// Package censys logic
package censys

import (
	"bytes"
	"context"
	"net/http"
	"strings"
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
	queryPrefix = "cert.names: "
	// authHeaderPrefix is the Bearer token prefix for Authorization header
	authHeaderPrefix = "Bearer "
	// contentTypeJSON is the Content-Type header value for JSON
	contentTypeJSON = "application/json"
	// orgIDHeader is the header name for organization ID
	orgIDHeader = "X-Organization-ID"
)

// apiKey holds the Personal Access Token and optional Organization ID
type apiKey struct {
	pat   string
	orgID string
}

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
	Hits          []hit  `json:"hits"`
	TotalHits     int64  `json:"total_hits"`
	NextPageToken string `json:"next_page_token"`
}

type hit struct {
	CertificateV1 certificateV1 `json:"certificate_v1"`
}

type certificateV1 struct {
	Resource resource `json:"resource"`
}

type resource struct {
	Names []string `json:"names"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []apiKey
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
		// (e.g., CENSYS_API_KEY=pat1:org1,pat2:org2) to distribute requests
		// and avoid hitting rate limits on a single key.
		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey.pat == "" {
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

			reqBody := searchRequest{
				Query:    queryPrefix + domain,
				Fields:   []string{"cert.names"},
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

			headers := map[string]string{
				"Content-Type":  contentTypeJSON,
				"Authorization": authHeaderPrefix + randomApiKey.pat,
			}
			// Add Organization ID header if provided
			if randomApiKey.orgID != "" {
				headers[orgIDHeader] = randomApiKey.orgID
			}

			resp, err := session.HTTPRequest(
				ctx,
				http.MethodPost,
				apiURL,
				"",
				headers,
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
			_ = resp.Body.Close()
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				return
			}

			for _, hit := range censysResponse.Result.Hits {
				for _, name := range hit.CertificateV1.Resource.Names {
					select {
					case <-ctx.Done():
						return
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: name}:
						s.results++
					}
				}
			}

			cursor = censysResponse.Result.NextPageToken
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

// AddApiKeys parses and adds API keys.
// Format: "PAT:ORG_ID" where ORG_ID is required for paid accounts.
// Example: "censys_xxx_token:12345678-91011-1213"
func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = subscraping.CreateApiKeys(keys, func(pat, orgID string) apiKey {
		return apiKey{pat: pat, orgID: orgID}
	})
	// Also support single PAT without org ID for free users
	for _, key := range keys {
		if !strings.Contains(key, ":") && key != "" {
			s.apiKeys = append(s.apiKeys, apiKey{pat: key, orgID: ""})
		}
	}
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
