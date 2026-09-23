// Package shodan logic
package shodan

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken atomic.Int64 // nanoseconds; cast to time.Duration on read
	errors    atomic.Int32
	results   atomic.Int32
	requests  atomic.Int32
	skipped   bool
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
	s.errors.Store(0)
	s.results.Store(0)
	s.requests.Store(0)

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken.Store(int64(time.Since(startTime)))
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
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
			s.requests.Add(1)
			resp, err := session.SimpleGet(ctx, searchURL)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
				session.DiscardHTTPResponse(resp)
				return
			}

			defer session.DiscardHTTPResponse(resp)

			var response dnsdbLookupResponse
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
				return
			}

			if response.Error != "" {
				results <- subscraping.Result{
					Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%v", response.Error),
				}
				s.errors.Add(1)
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
				s.results.Add(1)
				if maxResults > 0 && s.results >= maxResults {
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

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    int(s.errors.Load()),
		Results:   int(s.results.Load()),
		Requests:  int(s.requests.Load()),
		TimeTaken: time.Duration(s.timeTaken.Load()),
		Skipped:   s.skipped,
	}
}
