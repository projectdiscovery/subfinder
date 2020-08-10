package shodan

import (
	"context"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/pkg/subscraping/sources/shodan"
)

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.Shodan == "" {
			return
		}

		response, err := shodan.NewClient(
			ctx,
			"https://api.shodan.io",
			session.Keys.Shodan,
			session,
		).SSLLookupQuery(domain)

		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		for _, match := range response.Matches {
			for _, hostname := range match.Hostnames {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: hostname}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "shodan"
}
