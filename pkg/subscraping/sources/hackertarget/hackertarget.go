// Package hackertarget logic
package hackertarget

import (
	"bufio"
	"context"
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

		htSearchUrl := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey != "" {
			htSearchUrl = fmt.Sprintf("%s&apikey=%s", htSearchUrl, randomApiKey)
		}

		s.requests.Add(1)
		resp, err := session.SimpleGet(ctx, htSearchUrl)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			session.DiscardHTTPResponse(resp)
			return
		}

		defer func() {
			if err := resp.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
			}
		}()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			line := scanner.Text()
			if line == "" {
				continue
			}
			match := session.Extractor.Extract(line)
			for _, subdomain := range match {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					s.results.Add(1)
				}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "hackertarget"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.OptionalKey
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
		TimeTaken: time.Duration(s.timeTaken.Load()),
		Skipped:   s.skipped,
		Requests:  int(s.requests.Load()),
	}
}
