// Package chaos logic
package chaos

import (
	"context"
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
	requests  int
	skipped   bool
}

// normalizeSubdomain handles inconsistent upstream API responses where some domains
// return full subdomains (e.g., "mail.hotmail.com") while others return just the
// subdomain part (e.g., "mail"). #1778
func normalizeSubdomain(subdomain, domain string) string {
// normalizeSubdomain handles inconsistent upstream API responses where some domains
// return full subdomains (e.g., "mail.hotmail.com") while others return just the
// subdomain part (e.g., "mail"). #1778
func normalizeSubdomain(subdomain, domain string) string {
	if subdomain == domain {
		return subdomain
	}
	domainLen := len(domain)
	subdomainLen := len(subdomain)
	if subdomainLen > domainLen+1 && subdomain[subdomainLen-domainLen-1] == '.' && subdomain[subdomainLen-domainLen:] == domain {
		return subdomain
	}
	return subdomain + "." + domain
}
	domainLen := len(domain)
	subdomainLen := len(subdomain)
	value := subdomain + "." + domain
	if subdomainLen > domainLen+1 && subdomain[subdomainLen-domainLen-1] == '.' && subdomain[subdomainLen-domainLen:] == domain {
		value = subdomain
	}
	return value
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, _ *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0
	s.requests = 0

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
		s.requests++
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
			value := normalizeSubdomain(result.Subdomain, domain)
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Subdomain, Value: value,
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
