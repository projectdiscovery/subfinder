package shodandnsdb

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

		if session.Keys.ShodanDNSDB == "" {
			return
		}

		response, err := shodan.NewClient(
			ctx,
			"https://api.shodan.io",
			session.Keys.ShodanDNSDB,
			session,
		).DNSDBLookup(domain)

		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		for _, data := range response.Data {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: data.Subdomain}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "shodandnsdb"
}
