// Package thc logic
package thc

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Domains []struct {
		Domain string `json:"domain"`
	} `json:"domains"`
	NextPageState string `json:"next_page_state"`
}

// Source is the passive scraping agent
type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

type requestBody struct {
	Domain    string `json:"domain"`
	PageState string `json:"page_state"`
	Limit     int    `json:"limit"`
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

		var pageState string
		headers := map[string]string{"Content-Type": "application/json"}
		apiURL := "https://ip.thc.org/api/v1/lookup/subdomains"

		for {
			reqBody := requestBody{
				Domain:    domain,
				PageState: pageState,
				Limit:     1000,
			}

			bodyBytes, err := json.Marshal(reqBody)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				return
			}

			resp, err := session.Post(ctx, apiURL, "", headers, bytes.NewReader(bodyBytes))
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var thcResponse response
			err = jsoniter.NewDecoder(resp.Body).Decode(&thcResponse)
			session.DiscardHTTPResponse(resp)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				return
			}

			for _, domainRecord := range thcResponse.Domains {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: domainRecord.Domain}
				s.results++
			}

			pageState = thcResponse.NextPageState

			if pageState == "" {
				break
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "thc"
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
	// No API keys needed for THC
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
