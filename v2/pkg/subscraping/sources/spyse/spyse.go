// Package spyse logic
package spyse

import (
	"context"
	"fmt"
	"strconv"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type resultObject struct {
	Name string `json:"name"`
}

type dataObject struct {
	Items      []resultObject `json:"items"`
	TotalCount int            `json:"total_count"`
}

type errorObject struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type spyseResult struct {
	Data  dataObject    `json:"data"`
	Error []errorObject `json:"error"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.Spyse == "" {
			return
		}

		maxCount := 100

		for offSet := 0; offSet <= maxCount; offSet += 100 {
			resp, err := session.Get(ctx, fmt.Sprintf("https://api.spyse.com/v3/data/domain/subdomain?domain=%s&limit=100&offset=%s", domain, strconv.Itoa(offSet)), "", map[string]string{"Authorization": "Bearer " + session.Keys.Spyse})
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				session.DiscardHTTPResponse(resp)
				return
			}

			var response spyseResult
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			if response.Data.TotalCount == 0 {
				return
			}

			maxCount = response.Data.TotalCount

			for _, hostname := range response.Data.Items {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: hostname.Name}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "spyse"
}
