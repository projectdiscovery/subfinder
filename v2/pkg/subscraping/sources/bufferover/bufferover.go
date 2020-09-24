// Package bufferover is a bufferover Scraping Engine in Golang
package bufferover

import (
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Meta struct {
		Errors []string `json:"Errors"`
	} `json:"Meta"`
	FDNSA   []string `json:"FDNS_A"`
	RDNS    []string `json:"RDNS"`
	Results []string `json:"Results"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		// Run enumeration on subdomain dataset for historical SONAR datasets
		s.getData(ctx, fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain), session, results)
		s.getData(ctx, fmt.Sprintf("https://tls.bufferover.run/dns?q=.%s", domain), session, results)

		close(results)
	}()

	return results
}

func (s *Source) getData(ctx context.Context, sourceURL string, session *subscraping.Session, results chan subscraping.Result) {
	resp, err := session.SimpleGet(ctx, sourceURL)
	if err != nil && resp == nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		session.DiscardHTTPResponse(resp)
		return
	}

	var bufforesponse response
	err = jsoniter.NewDecoder(resp.Body).Decode(&bufforesponse)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		resp.Body.Close()
		return
	}

	resp.Body.Close()

	metaErrors := bufforesponse.Meta.Errors

	if len(metaErrors) > 0 {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", strings.Join(metaErrors, ", "))}
		return
	}

	var subdomains []string

	if len(bufforesponse.FDNSA) > 0 {
		subdomains = bufforesponse.FDNSA
		subdomains = append(subdomains, bufforesponse.RDNS...)
	} else if len(bufforesponse.Results) > 0 {
		subdomains = bufforesponse.Results
	}

	for _, subdomain := range subdomains {
		for _, value := range session.Extractor.FindAllString(subdomain, -1) {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: value}
		}
	}
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "bufferover"
}
