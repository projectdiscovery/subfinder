package zoomeyeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// search results
type zoomeyeResults struct {
	Status int `json:"status"`
	Total  int `json:"total"`
	List   []struct {
		Name string   `json:"name"`
		Ip   []string `json:"ip"`
	} `json:"list"`
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

		randomApiInfo := strings.Split(randomApiKey, ":")
		if len(randomApiInfo) != 2 {
			s.skipped = true
			return
		}
		host := randomApiInfo[0]
		apiKey := randomApiInfo[1]

		headers := map[string]string{
			"API-KEY":      apiKey,
			"Accept":       "application/json",
			"Content-Type": "application/json",
		}
		var pages = 1
		for currentPage := 1; currentPage <= pages; currentPage++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			api := fmt.Sprintf("https://api.%s/domain/search?q=%s&type=1&s=1000&page=%d", host, domain, currentPage)
			resp, err := session.Get(ctx, api, "", headers)
			isForbidden := resp != nil && resp.StatusCode == http.StatusForbidden
			if err != nil {
				if !isForbidden {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
					session.DiscardHTTPResponse(resp)
				}
				return
			}

			var res zoomeyeResults
			err = json.NewDecoder(resp.Body).Decode(&res)

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				_ = resp.Body.Close()
				return
			}
			_ = resp.Body.Close()
			pages = int(res.Total/1000) + 1
			for _, r := range res.List {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: r.Name}:
					s.results++
				}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "zoomeyeapi"
}

func (s *Source) IsDefault() bool {
	return false
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
