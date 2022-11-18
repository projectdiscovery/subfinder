// Package rapiddns is a RapidDNS Scraping Engine in Golang
package rapiddns

import (
	"context"
	"io"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// RapidDns is the Source that handles access to the RapidDns data source.
type RapidDns struct {
	*subscraping.Source
}

func NewRapidDns() *RapidDns {
	return &RapidDns{Source: &subscraping.Source{}}
}

// Run function returns all subdomains found with the service
func (r *RapidDns) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, "https://rapiddns.io/subdomain/"+domain+"?full=1")
		if err != nil {
			results <- subscraping.Result{Source: r.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: r.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		src := string(body)
		for _, subdomain := range session.Extractor.FindAllString(src, -1) {
			results <- subscraping.Result{Source: r.Name(), Type: subscraping.Subdomain, Value: subdomain}
		}
	}()

	return results
}

// Name returns the name of the source
func (r *RapidDns) Name() string {
	return "rapiddns"
}

func (r *RapidDns) SourceType() string {
	return subscraping.TYPE_SCRAPE
}
