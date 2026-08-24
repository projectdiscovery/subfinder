// Package crtname logic
package crtname

import (
	"bufio"
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const searchURL = "https://crt.name/v1/search?apex="

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0
	s.requests = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		s.requests++
		resp, err := s.fetch(ctx, domain, session)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		defer func() {
			if err := resp.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
			}
		}()

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
					s.results++
				}
				if maxResults > 0 && s.results >= maxResults {
					return
				}
			}
		}
		if err := scanner.Err(); err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
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
		Errors:    s.errors,
		Results:   s.results,
		Requests:  s.requests,
		TimeTaken: s.timeTaken,
	}
}
