package digitalyama

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"

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

type digitalYamaResponse struct {
	Query        string   `json:"query"`
	Count        int      `json:"count"`
	Subdomains   []string `json:"subdomains"`
	UsageSummary struct {
		QueryCost        float64 `json:"query_cost"`
		CreditsRemaining float64 `json:"credits_remaining"`
	} `json:"usage_summary"`
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

		searchURL := fmt.Sprintf("https://api.digitalyama.com/subdomain_finder?domain=%s", domain)
		s.requests.Add(1)
		resp, err := session.Get(ctx, searchURL, "", map[string]string{"x-api-key": randomApiKey})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			return
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
			}
		}()

		if resp.StatusCode != 200 {
			var errResponse struct {
				Detail []struct {
					Loc  []string `json:"loc"`
					Msg  string   `json:"msg"`
					Type string   `json:"type"`
				} `json:"detail"`
			}
			err = jsoniter.NewDecoder(resp.Body).Decode(&errResponse)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("unexpected status code %d", resp.StatusCode)}
				s.errors.Add(1)
				return
			}
			if len(errResponse.Detail) > 0 {
				errMsg := errResponse.Detail[0].Msg
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s (code %d)", errMsg, resp.StatusCode)}
			} else {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("unexpected status code %d", resp.StatusCode)}
			}
			s.errors.Add(1)
			return
		}

		var response digitalYamaResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			return
		}

		for _, subdomain := range response.Subdomains {
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
				s.results.Add(1)
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "digitalyama"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
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
