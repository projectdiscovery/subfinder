// Package urlscan logic
package urlscan

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
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
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.mu.Lock()
	apiKeys := s.apiKeys
	s.mu.Unlock()

	go func() {
		var stats subscraping.Statistics
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(apiKeys, s.Name())
		if randomApiKey == "" {
			stats.Skipped = true
			return
		}

		headers := map[string]string{"api-key": randomApiKey}

		// Search with wildcard to get more subdomain results
		s.enumerate(ctx, domain, headers, session, results, &stats)
	}()

	return results
}

// enumerate performs the actual enumeration with pagination
func (s *Source) enumerate(ctx context.Context, domain string, headers map[string]string, session *subscraping.Session, results chan subscraping.Result, stats *subscraping.Statistics) {
	var searchAfter string
	currentPage := 0

	// Honor an optional per-source result limit (0 = no limit) so a single
	// domain can't drain an API quota by paginating to the end.
	maxResults := session.MaxResults

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

		stats.Requests++
		resp, err := session.Get(ctx, searchURL, "", headers)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			stats.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var data response
		err = jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			stats.Errors++
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
						stats.Results++
					}
					if maxResults > 0 && stats.Results >= maxResults {
						return
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys = slices.Clone(keys)
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
