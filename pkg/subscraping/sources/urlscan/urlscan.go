// Package urlscan logic
package urlscan

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	// baseURL is the URLScan API base URL
	baseURL = "https://urlscan.io/api/v1/search/"
	// maxPages is the maximum number of pages to fetch (reduced due to strict rate limits)
	// URLScan has very strict burst limiting, so we limit to 3-5 pages max
	maxPages = 5
	// maxPerPage is the maximum results per page (URLScan max is 10000, but 100 is safer)
	maxPerPage = 100
	// maxRetries is the number of retry attempts for rate-limited requests
	// Reducing retries since each retry consumes quota
	maxRetries = 2
	// initialBackoff is the initial wait time before retrying (URLScan recommends waiting)
	initialBackoff = 20 * time.Second
	// paginationDelay is the delay between pagination requests to avoid rate limits
	// URLScan has 120 requests/minute but very strict burst limits
	// Using 8-10 seconds to be extra conservative
	paginationDelay = 10 * time.Second
)

// response represents the URLScan API response structure
type response struct {
	Results []struct {
		Task struct {
			Domain string `json:"domain"`
			URL    string `json:"url"`
		} `json:"task"`
		Page struct {
			Domain string `json:"domain"`
			URL    string `json:"url"`
		} `json:"page"`
		Sort []interface{} `json:"sort"`
	} `json:"results"`
	HasMore bool `json:"has_more"`
	Total   int  `json:"total"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
	skipped   bool
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0
	s.requests = 0
	s.skipped = false

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

		headers := map[string]string{"api-key": randomApiKey}

		// Search with wildcard to get more subdomain results
		s.enumerate(ctx, domain, headers, session, results)
	}()

	return results
}

// enumerate performs the actual enumeration with pagination
func (s *Source) enumerate(ctx context.Context, domain string, headers map[string]string, session *subscraping.Session, results chan subscraping.Result) {
	var searchAfter string
	currentPage := 0

	for {
		// Check context at the start of each iteration (standard pattern)
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Check max pages limit (similar to Censys)
		if currentPage >= maxPages {
			break
		}

		// Build search URL - search for domain and all subdomains
		searchURL := fmt.Sprintf("%s?q=domain:%s&size=%d", baseURL, url.QueryEscape(domain), maxPerPage)
		if searchAfter != "" {
			searchURL += "&search_after=" + url.QueryEscape(searchAfter)
		}

		resp, err := s.makeRequestWithRetry(ctx, session, searchURL, headers)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		var data response
		err = jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}
		session.DiscardHTTPResponse(resp)

		// Process results - extract subdomains from multiple fields
		for _, result := range data.Results {
			// Extract from task.domain, task.url, page.domain, page.url
			candidates := []string{
				result.Task.Domain,
				result.Page.Domain,
			}

			// Also extract from URLs if present
			if result.Task.URL != "" {
				if u, err := url.Parse(result.Task.URL); err == nil {
					candidates = append(candidates, u.Hostname())
				}
			}
			if result.Page.URL != "" {
				if u, err := url.Parse(result.Page.URL); err == nil {
					candidates = append(candidates, u.Hostname())
				}
			}

			for _, candidate := range candidates {
				if candidate == "" {
					continue
				}
				for _, subdomain := range session.Extractor.Extract(candidate) {
					select {
					case <-ctx.Done():
						return
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
						s.results++
					}
				}
			}
		}

		// Check pagination conditions (similar to Shodan/VirusTotal pattern)
		if !data.HasMore || len(data.Results) == 0 {
			break
		}

		// Get sort value for next page
		lastResult := data.Results[len(data.Results)-1]
		if len(lastResult.Sort) == 0 {
			break
		}

		// Build search_after parameter
		sortValues := make([]string, len(lastResult.Sort))
		for i, v := range lastResult.Sort {
			switch val := v.(type) {
			case float64:
				sortValues[i] = fmt.Sprintf("%.0f", val)
			default:
				sortValues[i] = fmt.Sprintf("%v", v)
			}
		}
		// Don't URL encode here - the session.Get will handle encoding
		searchAfter = strings.Join(sortValues, ",")
		currentPage++

		// Delay between pages to respect rate limits
		select {
		case <-ctx.Done():
			return
		case <-time.After(paginationDelay):
		}
	}
}

// makeRequestWithRetry handles rate limiting (429) and server errors (503) with exponential backoff
// This is necessary for URLScan as it has stricter rate limits than other sources
func (s *Source) makeRequestWithRetry(ctx context.Context, session *subscraping.Session, searchURL string, headers map[string]string) (*http.Response, error) {
	var resp *http.Response
	var err error
	backoff := initialBackoff

	for attempt := 0; attempt <= maxRetries; attempt++ {
		s.requests++
		resp, err = session.Get(ctx, searchURL, "", headers)

		// If request succeeded, return it
		if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		// Check for retryable status codes (429 rate limited, 503 server overload)
		if resp != nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) {
			// Try to get recommended wait time from X-Rate-Limit-Reset-After header
			resetAfter := resp.Header.Get("X-Rate-Limit-Reset-After")
			if resetAfter != "" {
				// Parse the seconds and use it as wait time
				if seconds, parseErr := time.ParseDuration(resetAfter + "s"); parseErr == nil && seconds > 0 {
					backoff = seconds + (2 * time.Second) // Add 2 extra seconds as buffer
				}
			}

			session.DiscardHTTPResponse(resp)

			if attempt < maxRetries {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(backoff):
					backoff *= 2 // Exponential backoff for next retry
				}
				continue
			}
			return nil, fmt.Errorf("rate limited (status %d) after %d retries", resp.StatusCode, maxRetries+1)
		}

		// For other errors (non-200, non-retryable status codes), return an error
		// This prevents callers from trying to decode error response bodies
		if resp != nil {
			status := resp.StatusCode
			session.DiscardHTTPResponse(resp)
			if err == nil {
				err = fmt.Errorf("unexpected status %d", status)
			}
		} else if err == nil {
			err = fmt.Errorf("unexpected nil response")
		}
		return nil, err
	}

	// This return is required by the Go compiler but is technically unreachable
	// since all paths in the loop above return
	return nil, fmt.Errorf("max retries exceeded")
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "urlscan"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		Requests:  s.requests,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
