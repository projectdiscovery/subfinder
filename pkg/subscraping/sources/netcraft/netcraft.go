// Package netcraft is a NetCraft Scraping Engine in Golang
package netcraft

import (
	"context"
	"io/ioutil"
	"regexp"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

var name = "netcraft"
var reNext = regexp.MustCompile("<a class=\"results-table__host\" href=\"(.*?)\".*>")

type Agent struct {
	Results chan subscraping.Result
	Session *subscraping.Session
}

func (a *Agent) enumerate(ctx context.Context, baseURL string, cookies string) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := a.Session.Get(ctx, baseURL, cookies, nil)
	if err != nil {
		a.Results <- subscraping.Result{Source: name, Type: subscraping.Error, Error: err}
		return
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		a.Results <- subscraping.Result{Source: name, Type: subscraping.Error, Error: err}
		return
	}

	src := string(body)

	gologger.Infof("netcraft", src)

	for _, subdomain := range a.Session.Extractor.FindAllString(src, -1) {
		a.Results <- subscraping.Result{Source: name, Type: subscraping.Subdomain, Value: subdomain}
	}

	match1 := reNext.FindStringSubmatch(src)
	if len(match1) > 0 {
		a.enumerate(ctx, match1[1], "")
	}
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	aInstance := Agent{
		Session: session,
		Results: results,
	}

	go func() {
		aInstance.enumerate(ctx, "https://searchdns.netcraft.com/?host=*." + domain, "")
		close(aInstance.Results)
	}()

	return aInstance.Results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return name
}
