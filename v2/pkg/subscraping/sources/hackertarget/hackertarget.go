// Package hackertarget logic
package hackertarget

import (
	"bufio"
	"context"
	"fmt"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("http://api.hackertarget.com/hostsearch/?q=%s", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			match := session.Extractor.FindAllString(line, -1)
			for _, subdomain := range match {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "hackertarget"
}
