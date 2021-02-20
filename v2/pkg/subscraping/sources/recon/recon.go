// Package recon logic
package recon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type subdomain struct {
	RawDomain string `json:"rawDomain"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.Recon == "" {
			return
		}

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://recon.dev/api/search?key=%s&domain=%s", session.Keys.Recon, domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var subdomains []subdomain
		err = json.NewDecoder(resp.Body).Decode(&subdomains)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		for _, subdomain := range subdomains {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain.RawDomain}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "recon"
}
