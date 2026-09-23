// Package certspotter logic
package certspotter

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type certspotterObject struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
}

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

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		// Honor an optional per-source result limit (0 = no limit) so a single
		// domain can't drain an API quota by paginating to the end.
		maxResults := session.MaxResults

		headers := map[string]string{"Authorization": "Bearer " + randomApiKey}
		cookies := ""

		s.requests.Add(1)
		resp, err := session.Get(ctx, fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain), cookies, headers)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			session.DiscardHTTPResponse(resp)
			return
		}

		var response []certspotterObject
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			session.DiscardHTTPResponse(resp)
			return
		}
		session.DiscardHTTPResponse(resp)

		for _, cert := range response {
			for _, subdomain := range cert.DNSNames {
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

		if len(response) == 0 {
			return
		}

		id := response[len(response)-1].ID
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			reqURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names&after=%s", domain, id)

			s.requests.Add(1)
			resp, err := session.Get(ctx, reqURL, cookies, headers)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
				return
			}

			var response []certspotterObject
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
				session.DiscardHTTPResponse(resp)
				return
			}
			session.DiscardHTTPResponse(resp)

			if len(response) == 0 {
				break
			}

			for _, cert := range response {
				for _, subdomain := range cert.DNSNames {
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

			id = response[len(response)-1].ID
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "certspotter"
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
