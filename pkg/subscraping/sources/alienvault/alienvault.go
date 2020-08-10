package alienvault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

type alienvaultResponse struct {
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
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			close(results)
			return
		}

		otxResp := &alienvaultResponse{}
		// Get the response body and decode
		err = json.NewDecoder(resp.Body).Decode(&otxResp)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			close(results)
			return
		}
		resp.Body.Close()
		for _, record := range otxResp.PassiveDNS {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Hostname}
		}
		close(results)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "alienvault"
}
