// Package onhype logic
package onhype

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type OnypheResponse struct {
	Error    int      `json:"error"`
	Results  []Result `json:"results"`
	Page     int      `json:"page"`
	PageSize int      `json:"page_size"`
	Total    int      `json:"total"`
}

type Result struct {
	Hostname string `json:"hostname"`
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

		headers := map[string]string{"Content-Type": "application/json", "Authorization": "bearer " + randomApiKey}

		page := 1
		for {
			var resp *http.Response
			var err error

			urlWithQuery := fmt.Sprintf("https://www.onyphe.io/api/v2/search/?q=%s&page=%d&size=10",
				url.QueryEscape("category:resolver domain:"+domain), page)
			resp, err = session.Get(ctx, urlWithQuery, "", headers)

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var respOnyphe OnypheResponse
			err = jsoniter.NewDecoder(resp.Body).Decode(&respOnyphe)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			session.DiscardHTTPResponse(resp)

			for _, record := range respOnyphe.Results {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Hostname}
				s.results++
			}

			if len(respOnyphe.Results) == 0 || (respOnyphe.Page)*respOnyphe.PageSize >= respOnyphe.Total {
				break
			}

			page++

		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "onhype"
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
