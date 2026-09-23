// Package crtname logic
package crtname

import (
	"bufio"
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const searchURL = "https://crt.name/v1/search?apex="

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
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

		s.requests.Add(1)
		resp, err := s.fetch(ctx, domain, session)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			session.DiscardHTTPResponse(resp)
			return
		}

		defer session.DiscardHTTPResponse(resp)

		maxResults := session.MaxResults
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "*.") {
				continue
			}

			for _, subdomain := range session.Extractor.Extract(line) {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					s.results.Add(1)
				}
				if maxResults > 0 && s.results >= maxResults {
					return
				}
			}
		}
		if err := scanner.Err(); err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
		}
	}()

	return results
}

func (s *Source) fetch(ctx context.Context, domain string, session *subscraping.Session) (*http.Response, error) {
	endpoint := searchURL + url.QueryEscape(domain)
	headers := map[string]string{"User-Agent": "subfinder"}
	if len(s.apiKeys) > 0 {
		headers["Authorization"] = "Bearer " + subscraping.PickRandom(s.apiKeys, s.Name())
	}
	return session.Get(ctx, endpoint, "", headers)
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "crtname"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
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
		Requests:  int(s.requests.Load()),
		TimeTaken: time.Duration(s.timeTaken.Load()),
	}
}
