package passivetotal

import (
	"bytes"
	"context"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

type response struct {
	Subdomains []string `json:"subdomains"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		if session.Keys.PassiveTotalUsername == "" || session.Keys.PassiveTotalPassword == "" {
			close(results)
			return
		}

		// Create JSON Get body
		var request = []byte(`{"query":"` + domain + `"}`)

		req, err := http.NewRequest("GET", "https://api.passivetotal.org/v2/enrichment/subdomains", bytes.NewBuffer(request))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		req.SetBasicAuth(session.Keys.PassiveTotalUsername, session.Keys.PassiveTotalPassword)
		req.Header.Set("Content-Type", "application/json")

		resp, err := session.Client.Do(req)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		data := response{}
		err = jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			close(results)
			return
		}
		resp.Body.Close()

		for _, subdomain := range data.Subdomains {
			finalSubdomain := subdomain + "." + domain
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: finalSubdomain}
		}
		close(results)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "passivetotal"
}
