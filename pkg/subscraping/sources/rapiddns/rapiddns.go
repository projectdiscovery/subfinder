// Package rapiddns is a RapidDNS Scraping Engine in Golang
package rapiddns

import (
	"context"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// RapidDNS is a struct for archiveurlsagent
type RapidDNS struct {
	Results chan subscraping.Result
	Session *subscraping.Session
}

var reNext = regexp.MustCompile("<td><a href=\"(.*?)\" target=\"_blank\">.*?</a></td>")

func (a *RapidDNS) enumerate(ctx context.Context, baseURL string) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := a.Session.NormalGetWithContext(ctx, baseURL)
	if err != nil {
		a.Results <- subscraping.Result{Source: "radpiddns", Type: subscraping.Error, Error: err}
		return
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		a.Results <- subscraping.Result{Source: "radpiddns", Type: subscraping.Error, Error: err}
		return
	}

	src := string(body)

	for _, subdomain := range a.Session.Extractor.FindAllString(src, -1) {
		a.Results <- subscraping.Result{Source: "radpiddns", Type: subscraping.Subdomain, Value: subdomain}
	}

	match1 := reNext.FindStringSubmatch(src)
	if len(match1) > 0 {
		a.enumerate(ctx, strings.TrimRight(match1[1], " "))
	}
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	aInstance := RapidDNS{
		Session: session,
		Results: results,
	}

	go func() {
		aInstance.enumerate(ctx, "https://rapiddns.io/subdomain/"+domain+"?full=1")
		close(aInstance.Results)
	}()

	return aInstance.Results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "rapiddns"
}
