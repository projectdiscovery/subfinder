// Package alienvault logic
package alienvault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type alienvaultResponse struct {
	Detail     string `json:"detail"`
	Error      string `json:"error"`
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain))
		if err != nil && resp == nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response alienvaultResponse
		// Get the response body and decode
		err = json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if response.Error != "" {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s, %s", response.Detail, response.Error)}
			return
		}

		for _, record := range response.PassiveDNS {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Hostname}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "alienvault"
}
