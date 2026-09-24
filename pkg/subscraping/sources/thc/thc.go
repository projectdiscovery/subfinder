// Package thc logic
package thc

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
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
	mu    sync.Mutex
	stats subscraping.Statistics
}

type requestBody struct {
	Domain    string `json:"domain"`
	PageState string `json:"page_state"`
	Limit     int    `json:"limit"`
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		var stats subscraping.Statistics
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
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
				stats.Errors++
				return
			}

			stats.Requests++
			resp, err := session.Post(ctx, apiURL, "", headers, bytes.NewReader(bodyBytes))
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var thcResponse response
			err = jsoniter.NewDecoder(resp.Body).Decode(&thcResponse)
			session.DiscardHTTPResponse(resp)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				return
			}

			for _, domainRecord := range thcResponse.Domains {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: domainRecord.Domain}
				stats.Results++
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
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(_ []string) {
	// No API keys needed for THC
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
