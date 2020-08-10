package entrust

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://ctsearch.entrust.com/api/v1/certificates?fields=issuerCN,subjectO,issuerDN,issuerO,subjectDN,signAlg,san,publicKeyType,publicKeySize,validFrom,validTo,sn,ev,logEntries.logName,subjectCNReversed,cert&domain=%s&includeExpired=true&exactMatch=false&limit=5000", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		src := string(body)
		for _, subdomain := range session.Extractor.FindAllString(src, -1) {
			subdomain = strings.TrimPrefix(subdomain, "u003d")

			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "entrust"
}
