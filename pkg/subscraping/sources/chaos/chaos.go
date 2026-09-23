// Package chaos logic
package chaos

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/chaos-client/pkg/chaos"
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
func (s *Source) Run(ctx context.Context, domain string, _ *subscraping.Session) <-chan subscraping.Result {
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

		chaosClient := chaos.New(randomApiKey)
		s.requests.Add(1)
		for result := range chaosClient.GetSubdomains(&chaos.SubdomainsRequest{
			Domain: domain,
		}) {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if result.Error != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: result.Error}
				s.errors.Add(1)
				break
			}
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Subdomain, Value: fmt.Sprintf("%s.%s", result.Subdomain, domain),
			}
			s.results.Add(1)
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "chaos"
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
