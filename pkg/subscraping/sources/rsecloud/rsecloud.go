package rsecloud

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Count      int      `json:"count"`
	Data       []string `json:"data"`
	Page       int      `json:"page"`
	PageSize   int      `json:"pagesize"`
	TotalPages int      `json:"total_pages"`
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

		// Honor an optional per-source result limit (0 = no limit) so a single
		// domain can't drain an API quota by paginating to the end.
		maxResults := session.MaxResults

		headers := map[string]string{"Content-Type": "application/json", "X-API-Key": randomApiKey}

		fetchSubdomains := func(endpoint string) {
			page := 1
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				stats.Requests++
				resp, err := session.Get(ctx, fmt.Sprintf("https://api.rsecloud.com/api/v2/subdomains/%s/%s?page=%d", endpoint, domain, page), "", headers)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					stats.Errors++
					session.DiscardHTTPResponse(resp)
					return
				}

				var rseCloudResponse response
				err = jsoniter.NewDecoder(resp.Body).Decode(&rseCloudResponse)
				session.DiscardHTTPResponse(resp)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					stats.Errors++
					return
				}

				for _, subdomain := range rseCloudResponse.Data {
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

				if page >= rseCloudResponse.TotalPages {
					break
				}
				page++
			}
		}

		fetchSubdomains("active")
		if maxResults > 0 && stats.Results >= maxResults {
			return
		}
		fetchSubdomains("passive")
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "rsecloud"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
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
