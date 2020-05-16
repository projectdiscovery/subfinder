package alienvault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

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
		resp, err := session.NormalGetWithContext(ctx, fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}
		if resp.StatusCode != 200 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("invalid status code received: %d", resp.StatusCode)}
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
			close(results)
			return
		}
		defer resp.Body.Close()
		otxResp := &alienvaultResponse{}
		// Get the response body and decode
		err = json.NewDecoder(resp.Body).Decode(&otxResp)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			close(results)
			return
		}

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
