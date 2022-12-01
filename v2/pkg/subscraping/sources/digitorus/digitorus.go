// Package waybackarchive logic
package digitorus

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Digitorus is the Source that handles access to the Digitorus data source.
type Digitorus struct {
	*subscraping.Source
}

func NewDigitorus() *Digitorus {
	return &Digitorus{Source: &subscraping.Source{}}
}

// Run function returns all subdomains found with the service
func (d *Digitorus) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://certificatedetails.com/%s", domain))
		if err != nil {
			results <- subscraping.Result{Source: d.Name(), Type: subscraping.Error, Error: err}
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
			subdomains := session.Extractor.FindAllString(line, -1)
			for _, subdomain := range subdomains {
				results <- subscraping.Result{Source: d.Name(), Type: subscraping.Subdomain, Value: strings.TrimPrefix(subdomain, ".")}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (d *Digitorus) Name() string {
	return "digitorus"
}

func (d *Digitorus) IsDefault() bool {
	return true
}

func (d *Digitorus) HasRecursiveSupport() bool {
	return true
}

func (d *Digitorus) SourceType() string {
	return subscraping.TYPE_CERT
}
