package binaryedge

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

type binaryedgeResponse struct {
	Subdomains []string `json:"events"`
	Total      int      `json:"total"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		if session.Keys.Binaryedge == "" {
			close(results)
			return
		}

		resp, err := session.Get(fmt.Sprintf("https://api.binaryedge.io/v2/query/domains/subdomain/%s", domain), "", map[string]string{"X-Key": session.Keys.Binaryedge})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		response := new(binaryedgeResponse)
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			close(results)
			return
		}
		resp.Body.Close()

		for _, subdomain := range response.Subdomains {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
		}

		remaining := response.Total - 100
		currentPage := 2

		for {
			further := s.getSubdomains(ctx, domain, &remaining, &currentPage, session, results)
			if !further {
				break
			}
		}
		close(results)
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
			resp, err := session.Get(fmt.Sprintf("https://api.binaryedge.io/v2/query/domains/subdomain/%s?page=%d", domain, *currentPage), "", map[string]string{"X-Key": session.Keys.Binaryedge})
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				return false
			}

			response := binaryedgeResponse{}
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

			*remaining = *remaining - 100
			if *remaining <= 0 {
				return false
			}
			*currentPage++
			return true
		}
	}
}
