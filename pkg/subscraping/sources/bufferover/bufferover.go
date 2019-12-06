// Package bufferover is a bufferover Scraping Engine in Golang
package bufferover

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		// Run enumeration on subdomain dataset for historical SONAR datasets
		s.getData(fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain), session, results)
		s.getData(fmt.Sprintf("https://tls.bufferover.run/dns?q=.%s", domain), session, results)

		close(results)
	}()

	return results
}

func (s *Source) getData(URL string, session Session, results chan subscraping.Result) {
	resp, err := session.NormalGet(URL)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		return
	}
	resp.Body.Close()

	src := string(body)

	for _, subdomain := range session.GetExtractor().FindAllString(src, -1) {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
	}
	return
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "bufferover"
}

// Session is an interface of *subscraping.Session, created temporarily to make this package testable.
// TODO: A full version of this interface may be placed in upper level.
type Session interface {
	NormalGetter
	Extractor
}

// NormalGetter represents the ability to make an HTTP(s) GET request.
type NormalGetter interface {
	NormalGet(url string) (*http.Response, error)
}

// Extractor represents the ability to get an regex.
type Extractor interface {
	GetExtractor() *regexp.Regexp
}
