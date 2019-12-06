package waybackarchive

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
		pagesResp, err := session.NormalGet(fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		body, err := ioutil.ReadAll(pagesResp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			pagesResp.Body.Close()
			close(results)
			return
		}
		pagesResp.Body.Close()

		match := session.Extractor.FindAllString(string(body), -1)
		for _, subdomain := range match {
			subdomain = strings.TrimPrefix(subdomain, "25")
			subdomain = strings.TrimPrefix(subdomain, "2F")

			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
		}
		close(results)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "waybackarchive"
}
