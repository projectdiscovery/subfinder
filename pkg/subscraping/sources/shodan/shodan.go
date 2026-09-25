// Package shodan logic
package shodan

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

type dnsdbLookupResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Result     int      `json:"result"`
	Error      string   `json:"error"`
	More       bool     `json:"more"`
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

		page := 1
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			searchURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s&page=%d", domain, randomApiKey, page)
			stats.Requests++
			resp, err := session.SimpleGet(ctx, searchURL)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			defer session.DiscardHTTPResponse(resp)

			var response dnsdbLookupResponse
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				return
			}

			if response.Error != "" {
				results <- subscraping.Result{
					Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%v", response.Error),
				}
				stats.Errors++
				return
			}

			for _, data := range response.Subdomains {
				select {
				case <-ctx.Done():
					return
				default:
				}
				value := fmt.Sprintf("%s.%s", data, response.Domain)
				results <- subscraping.Result{
					Source: s.Name(), Type: subscraping.Subdomain, Value: value,
				}
				stats.Results++
				if maxResults > 0 && stats.Results >= maxResults {
					return
				}
			}

			if !response.More {
				break
			}
			page++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "shodan"
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

// AddApiKeys copies keys for subsequent runs.
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
