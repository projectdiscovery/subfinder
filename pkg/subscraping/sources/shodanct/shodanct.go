// Package shodanct logic
package shodanct

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	timeTaken atomic.Int64 // nanoseconds; cast to time.Duration on read
	errors    atomic.Int32
	results   atomic.Int32
	requests  atomic.Int32
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

		searchURL := fmt.Sprintf("https://ctl.shodan.io/api/v1/domain/%s/hostnames", domain)
		s.requests.Add(1)
		resp, err := session.SimpleGet(ctx, searchURL)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			session.DiscardHTTPResponse(resp)
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Error,
				Error: fmt.Errorf("unexpected status code %d received from %s", resp.StatusCode, searchURL),
			}
			s.errors.Add(1)
			session.DiscardHTTPResponse(resp)
			return
		}

		defer session.DiscardHTTPResponse(resp)

		var hostnames []string
		if err := jsoniter.NewDecoder(resp.Body).Decode(&hostnames); err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			return
		}

		for _, hostname := range hostnames {
			for _, subdomain := range session.Extractor.Extract(hostname) {
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
	return "shodanct"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    int(s.errors.Load()),
		Results:   int(s.results.Load()),
		Requests:  int(s.requests.Load()),
		TimeTaken: time.Duration(s.timeTaken.Load()),
	}
}
