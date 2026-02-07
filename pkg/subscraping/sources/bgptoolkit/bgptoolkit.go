// Package bgptoolkit logic
package bgptoolkit

import (
	"context"
	"fmt"
	"net/url"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type apiDomain struct {
	Domain string `json:"domain"`
}

type apiResponse struct {
	Domains []apiDomain `json:"domains"`
}

// Source is the passive scraping agent
// using BGP Toolkit certificate transparency search.
type Source struct {
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

		endpoint := fmt.Sprintf("https://bgp.he.net/certs/api/list?domain=%s", url.QueryEscape(domain))
		s.requests++
		resp, err := session.SimpleGet(ctx, endpoint)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var data apiResponse
		if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}
		session.DiscardHTTPResponse(resp)

		for _, entry := range data.Domains {
			select {
			case <-ctx.Done():
				return
			default:
			}

			for _, value := range session.Extractor.Extract(entry.Domain) {
				if value == "" {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: value}:
					s.results++
				}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "bgptoolkit"
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
		Errors:    s.errors,
		Results:   s.results,
		Requests:  s.requests,
		TimeTaken: s.timeTaken,
	}
}
