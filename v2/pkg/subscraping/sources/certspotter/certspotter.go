// Package certspotter logic
package certspotter

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type certspotterObject struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.Certspotter == "" {
			return
		}

		resp, err := session.Get(ctx, fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain), "", map[string]string{"Authorization": "Bearer " + session.Keys.Certspotter})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response []certspotterObject
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		for _, cert := range response {
			for _, subdomain := range cert.DNSNames {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}
		}

		// if the number of responses is zero, close the channel and return.
		if len(response) == 0 {
			return
		}

		id := response[len(response)-1].ID
		for {
			reqURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names&after=%s", domain, id)

			resp, err := session.Get(ctx, reqURL, "", map[string]string{"Authorization": "Bearer " + session.Keys.Certspotter})
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				return
			}

			var response []certspotterObject
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			if len(response) == 0 {
				break
			}

			for _, cert := range response {
				for _, subdomain := range cert.DNSNames {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
				}
			}

			id = response[len(response)-1].ID
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "certspotter"
}
