// Package merklemap logic
package merklemap

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Results []struct {
		Domain string `json:"domain"`
	} `json:"results"`
}

// Source is the passive scraping agent
type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
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

		var page int
		for {
			var url string = fmt.Sprintf("https://api.merklemap.com/search?stream=true&stream_progress=true&query=*.%s&page=%d", domain, page)
			resp, err := session.SimpleGet(ctx, url)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}
			defer resp.Body.Close()

			var data response
			err = jsoniter.NewDecoder(resp.Body).Decode(&data)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				return
			}

			if len(data.Results) == 0 {
				break
			}

			for _, record := range data.Results {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Domain}
				s.results++
			}

			page++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "merklemap"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
