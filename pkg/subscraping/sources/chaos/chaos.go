// Package chaos logic
package chaos

import (
	"context"
	"fmt"
	"time"

	"github.com/projectdiscovery/chaos-client/pkg/chaos"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, _ *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

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

		chaosClient := chaos.New(randomApiKey)
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
				s.errors++
				break
			}
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Subdomain, Value: fmt.Sprintf("%s.%s", result.Subdomain, domain),
			}
			s.results++
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
