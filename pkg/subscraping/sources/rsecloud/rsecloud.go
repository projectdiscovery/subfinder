package rsecloud

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Count      int      `json:"count"`
	Data       []string `json:"data"`
	Page       int      `json:"page"`
	PageSize   int      `json:"pagesize"`
	TotalPages int      `json:"total_pages"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
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

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		headers := map[string]string{"Content-Type": "application/json", "X-API-Key": randomApiKey}

		fetchSubdomains := func(endpoint string) {
			page := 1
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				resp, err := session.Get(ctx, fmt.Sprintf("https://api.rsecloud.com/api/v2/subdomains/%s/%s?page=%d", endpoint, domain, page), "", headers)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
					session.DiscardHTTPResponse(resp)
					return
				}

				var rseCloudResponse response
				err = jsoniter.NewDecoder(resp.Body).Decode(&rseCloudResponse)
				session.DiscardHTTPResponse(resp)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
					return
				}

				for _, subdomain := range rseCloudResponse.Data {
					select {
					case <-ctx.Done():
						return
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
						s.results++
					}
				}

				if page >= rseCloudResponse.TotalPages {
					break
				}
				page++
			}
		}

		fetchSubdomains("active")
		fetchSubdomains("passive")
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "rsecloud"
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
