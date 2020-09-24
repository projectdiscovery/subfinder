package certspotterold

import (
	"context"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"Message"`
}

type subdomain struct {
	DNSNames []string `json:"dns_names"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://certspotter.com/api/v0/certs?domain=%s", domain))
		if err != nil && resp == nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		if resp.StatusCode != http.StatusOK {
			var errResponse errorResponse
			err = jsoniter.NewDecoder(resp.Body).Decode(&errResponse)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return
			}

			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s: %s", errResponse.Code, errResponse.Message)}
			resp.Body.Close()
			return
		}

		var subdomains []subdomain
		err = jsoniter.NewDecoder(resp.Body).Decode(&subdomains)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		for _, subdomain := range subdomains {
			for _, dnsname := range subdomain.DNSNames {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: dnsname}
			}
		}
	}()
	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "certspotterold"
}
