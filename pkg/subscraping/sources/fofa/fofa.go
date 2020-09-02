package fofa

import (
	"context"
	"fmt"

	"github.com/fofapro/fofa-go/fofa"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.FofaEmail == "" || session.Keys.FofaKey == "" {
			return
		}

		clt := fofa.NewFofaClient([]byte(session.Keys.FofaEmail), []byte(session.Keys.FofaKey))
		if clt == nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("could no create the fofa client")}
			return
		}

		query := []byte(fmt.Sprintf(`domain="%s"`, domain))
		fields := []byte("host, title")

		arr, err := clt.QueryAsArray(1, query, fields)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		for _, result := range arr {
			subdomain := session.Extractor.FindString(result.Host)
			if subdomain != "" {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "fofa"
}
