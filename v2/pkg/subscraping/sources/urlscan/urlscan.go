// Package urlscan logic
package urlscan

import (
	"context"
	"fmt"
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Results []Result `json:"results"`
	HasMore bool     `json:"has_more"`
}

type Result struct {
	Page Page          `json:"page"`
	Sort []interface{} `json:"sort"`
}

type Page struct {
	Domain string `json:"domain"`
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
			return
		}

		var hasMore bool = true
		var searchAfter string
		headers := map[string]string{"API-Key": randomApiKey}
		var url string = fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", domain)
		for hasMore {
			if searchAfter != "" {
				url = fmt.Sprintf("%s&search_after=%s", url, searchAfter)
			}

			resp, err := session.Get(ctx, url, "", headers)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var data response
			err = jsoniter.NewDecoder(resp.Body).Decode(&data)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				resp.Body.Close()
				return
			}

			resp.Body.Close()

			for _, subdomain := range data.Results {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain.Page.Domain}
				s.results++
			}
			if len(data.Results) > 0 {
				lastResult := data.Results[len(data.Results)-1]
				if len(lastResult.Sort) > 0 {
					sort1 := strconv.Itoa(int(lastResult.Sort[0].(float64)))
					sort2, _ := lastResult.Sort[1].(string)

					searchAfter = fmt.Sprintf("%s,%s", sort1, sort2)
				}
			}
			hasMore = data.HasMore
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "urlscan"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
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
