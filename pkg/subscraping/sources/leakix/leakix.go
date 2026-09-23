// Package leakix logic
package leakix

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

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
		// Default headers
		headers := map[string]string{
			"accept": "application/json",
		}
		// Pick an API key
		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey != "" {
			headers["api-key"] = randomApiKey
		}
		// Request
		s.requests.Add(1)
		resp, err := session.Get(ctx, "https://leakix.net/api/subdomains/"+domain, "", headers)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			return
		}

		defer session.DiscardHTTPResponse(resp)

		if resp.StatusCode != 200 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("request failed with status %d", resp.StatusCode)}
			s.errors.Add(1)
			return
		}
		// Parse and return results
		var subdomains []subResponse
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&subdomains)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			return
		}
		for _, result := range subdomains {
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: result.Subdomain}:
				s.results.Add(1)
			}
		}
	}()
	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "leakix"
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
		Errors:    int(s.errors.Load()),
		Results:   int(s.results.Load()),
		Requests:  int(s.requests.Load()),
		TimeTaken: time.Duration(s.timeTaken.Load()),
		Skipped:   s.skipped,
	}
}

type subResponse struct {
	Subdomain   string    `json:"subdomain"`
	DistinctIps int       `json:"distinct_ips"`
	LastSeen    time.Time `json:"last_seen"`
}
