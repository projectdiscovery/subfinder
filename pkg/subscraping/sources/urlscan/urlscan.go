// Package urlscan logic
package urlscan

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	// baseURL is the URLScan API base URL
	baseURL = "https://urlscan.io/api/v1/search/"
	// maxPages is the maximum number of pages to fetch
	maxPages = 5
	// maxPerPage is the maximum results per page (URLScan max is 10000, but 100 is safer)
	maxPerPage = 100
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
		select {
		case <-ctx.Done():
			return
		default:
		}

		if currentPage >= maxPages {
			break
		}

		// Build search URL
		searchURL := fmt.Sprintf("%s?q=domain:%s&size=%d", baseURL, url.QueryEscape(domain), maxPerPage)
		if searchAfter != "" {
			searchURL += "&search_after=" + url.QueryEscape(searchAfter)
		}

		s.requests++
		resp, err := session.Get(ctx, searchURL, "", headers)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
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

		// Check pagination conditions
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
		searchAfter = strings.Join(sortValues, ",")
		currentPage++
	}
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
