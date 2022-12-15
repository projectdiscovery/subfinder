// Package waybackarchive logic
package waybackarchive

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// WaybackArchive is the Source that handles access to the WaybackArchive data source.
type WaybackArchive struct {
	*subscraping.Source
}

func NewWaybackArchive() *WaybackArchive {
	return &WaybackArchive{Source: &subscraping.Source{Errors: 0, Results: 0}}
}

// Run function returns all subdomains found with the service
func (w *WaybackArchive) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			w.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey", domain))
		if err != nil {
			results <- subscraping.Result{Source: w.Name(), Type: subscraping.Error, Error: err}
			w.Errors++
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
			line, _ = url.QueryUnescape(line)
			subdomain := session.Extractor.FindString(line)
			if subdomain != "" {
				// fix for triple encoded URL
				subdomain = strings.ToLower(subdomain)
				subdomain = strings.TrimPrefix(subdomain, "25")
				subdomain = strings.TrimPrefix(subdomain, "2f")

				results <- subscraping.Result{Source: w.Name(), Type: subscraping.Subdomain, Value: subdomain}
				w.Results++
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (w *WaybackArchive) Name() string {
	return "waybackarchive"
}

func (w *WaybackArchive) SourceType() string {
	return subscraping.TYPE_ARCHIVE
}
