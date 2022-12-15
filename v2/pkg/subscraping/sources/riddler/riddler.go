// Package riddler logic
package riddler

import (
	"bufio"
	"context"
	"fmt"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Riddler is the Source that handles access to the Riddler data source.
type Riddler struct {
	*subscraping.Source
}

func NewRiddler() *Riddler {
	return &Riddler{Source: &subscraping.Source{Errors: 0, Results: 0}}
}

// Run function returns all subdomains found with the service
func (r *Riddler) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			r.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://riddler.io/search?q=pld:%s&view_type=data_table", domain))
		if err != nil {
			results <- subscraping.Result{Source: r.Name(), Type: subscraping.Error, Error: err}
			r.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			subdomain := session.Extractor.FindString(line)
			if subdomain != "" {
				results <- subscraping.Result{Source: r.Name(), Type: subscraping.Subdomain, Value: subdomain}
				r.Results++
			}
		}
		resp.Body.Close()
	}()

	return results
}

// Name returns the name of the source
func (r *Riddler) Name() string {
	return "riddler"
}

func (r *Riddler) IsDefault() bool {
	return true
}

func (r *Riddler) SourceType() string {
	return subscraping.TYPE_SCRAPE
}
