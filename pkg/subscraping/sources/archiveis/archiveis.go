// Package archiveis is a Archiveis Scraping Engine in Golang
package archiveis

import (
	"context"
	"io/ioutil"
	"regexp"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// ArchiveIs is a struct for archiveurlsagent
type ArchiveIs struct {
	Results chan subscraping.Result
	Session *subscraping.Session

	closed bool
}

var reNext = regexp.MustCompile("<a id=\"next\" style=\".*\" href=\"(.*)\">&rarr;</a>")

func (a *ArchiveIs) enumerate(ctx context.Context, baseURL string) {
	for {
		select {
		case <-ctx.Done():
			close(a.Results)
			return
		default:
			resp, err := a.Session.NormalGet(baseURL)
			if err != nil {
				a.Results <- subscraping.Result{Source: "archiveis", Type: subscraping.Error, Error: err}
				close(a.Results)
				return
			}

			// Get the response body
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				a.Results <- subscraping.Result{Source: "archiveis", Type: subscraping.Error, Error: err}
				resp.Body.Close()
				close(a.Results)
				return
			}
			resp.Body.Close()

			src := string(body)

			for _, subdomain := range a.Session.Extractor.FindAllString(src, -1) {
				a.Results <- subscraping.Result{Source: "archiveis", Type: subscraping.Subdomain, Value: subdomain}
			}

			match1 := reNext.FindStringSubmatch(src)
			if len(match1) > 0 {
				a.enumerate(ctx, match1[1])
			}

			// Guard channel closing during recursion
			if !a.closed {
				close(a.Results)
				a.closed = true
			}
			return
		}
	}
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	aInstance := ArchiveIs{
		Session: session,
		Results: results,
	}

	go aInstance.enumerate(ctx, "http://archive.is/*."+domain)

	return aInstance.Results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "archiveis"
}
