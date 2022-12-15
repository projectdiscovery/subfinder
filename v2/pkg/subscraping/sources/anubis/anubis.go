// Package anubis logic
package anubis

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Anubis is the Source that handles access to the Anubis data source.
type Anubis struct {
	*subscraping.Source
}

func NewAnubis() *Anubis {
	return &Anubis{Source: &subscraping.Source{Errors: 0, Results: 0}}
}

// Run function returns all subdomains found with the service
func (a *Anubis) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			a.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://jonlu.ca/anubis/subdomains/%s", domain))
		if err != nil {
			results <- subscraping.Result{Source: a.Name(), Type: subscraping.Error, Error: err}
			a.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var subdomains []string
		err = jsoniter.NewDecoder(resp.Body).Decode(&subdomains)
		if err != nil {
			results <- subscraping.Result{Source: a.Name(), Type: subscraping.Error, Error: err}
			a.Errors++
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		for _, record := range subdomains {
			results <- subscraping.Result{Source: a.Name(), Type: subscraping.Subdomain, Value: record}
			a.Results++
		}

	}()

	return results
}

// Name returns the name of the source
func (a *Anubis) Name() string {
	return "anubis"
}

func (a *Anubis) IsDefault() bool {
	return true
}

func (a *Anubis) SourceType() string {
	return subscraping.TYPE_API
}
