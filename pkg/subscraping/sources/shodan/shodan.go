// Package shodan logic
package shodan

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

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

type dnsdbLookupResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Result     int      `json:"result"`
	Error      string   `json:"error"`
	More       bool     `json:"more"`
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
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

		page := 1
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			searchURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s&page=%d", domain, randomApiKey, page)
			resp, err := session.SimpleGet(ctx, searchURL)
			if err != nil {
				session.DiscardHTTPResponse(resp)
				return
			}

			defer session.DiscardHTTPResponse(resp)

			var response dnsdbLookupResponse
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				return
			}

			if response.Error != "" {
				results <- subscraping.Result{
					Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%v", response.Error),
				}
				s.errors++
				return
			}

			for _, data := range response.Subdomains {
				select {
				case <-ctx.Done():
					return
				default:
				}
				value := fmt.Sprintf("%s.%s", data, response.Domain)
				results <- subscraping.Result{
					Source: s.Name(), Type: subscraping.Subdomain, Value: value,
				}
				s.results++
			}

			if !response.More {
				break
			}
			page++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "shodan"
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
