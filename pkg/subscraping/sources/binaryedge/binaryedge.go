package binaryedge

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

type binaryedgeResponse struct {
	Subdomains []string `json:"events"`
	PageSize   int      `json:"pagesize"`
	Total      int      `json:"total"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.Binaryedge == "" {
			return
		}

		resp, err := session.Get(ctx, fmt.Sprintf("https://api.binaryedge.io/v2/query/domains/subdomain/%s?pagesize=10000", domain), "", map[string]string{"X-Key": session.Keys.Binaryedge})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			// Try enterprise v1 api if key does not work for v2 api
			// provide a large pagesize it will shrink to the max supported by your account
			resp, err = session.Get(ctx, fmt.Sprintf("https://api.binaryedge.io/v1/query/domains/subdomain/%s?pagesize=10000", domain), "", map[string]string{"X-Token": session.Keys.Binaryedge})
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				session.DiscardHTTPResponse(resp)
				return
			}
		}

		var response binaryedgeResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		for _, subdomain := range response.Subdomains {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
		}

		remaining := response.Total - response.PageSize
		currentPage := 2

		for {
			further := s.getSubdomains(ctx, domain, &remaining, &currentPage, session, results)
			if !further {
				break
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "binaryedge"
}

func (s *Source) getSubdomains(ctx context.Context, domain string, remaining, currentPage *int, session *subscraping.Session, results chan subscraping.Result) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		default:
			resp, err := session.Get(ctx, fmt.Sprintf("https://api.binaryedge.io/v2/query/domains/subdomain/%s?page=%d&pagesize=%d", domain, *currentPage, 10000), "", map[string]string{"X-Key": session.Keys.Binaryedge})
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				// Try enterprise v1 api if key does not work for v2 api
				// Provide a large pagesize it will shrink to the max supported by your account
				resp, err = session.Get(ctx, fmt.Sprintf("https://api.binaryedge.io/v1/query/domains/subdomain/%s?page=%d&pagesize=%d", domain, *currentPage, 10000), "", map[string]string{"X-Token": session.Keys.Binaryedge})
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					return false
				}
			}

			var response binaryedgeResponse
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return false
			}
			resp.Body.Close()

			for _, subdomain := range response.Subdomains {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}

			*remaining -= response.PageSize
			if *remaining <= 0 {
				return false
			}
			*currentPage++
			return true
		}
	}
}
