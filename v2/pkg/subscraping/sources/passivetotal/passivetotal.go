// Package passivetotal logic
package passivetotal

import (
	"bytes"
	"context"
	"regexp"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

var passiveTotalFilterRegex = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}\\032`)

type response struct {
	Subdomains []string `json:"subdomains"`
}

// PassiveTotal is the CredsKeyApiSource that handles access to the PassiveTotal data source.
type PassiveTotal struct {
	*subscraping.MultiPartKeyApiSource
}

func NewPassiveTotal() *PassiveTotal {
	return &PassiveTotal{
		MultiPartKeyApiSource: &subscraping.MultiPartKeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

// Run function returns all subdomains found with the service
func (p *PassiveTotal) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			p.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(p.ApiKeys(), p.Name())
		if randomApiKey.Username == "" || randomApiKey.Password == "" {
			p.Skipped = true
			return
		}

		// Create JSON Get body
		var request = []byte(`{"query":"` + domain + `"}`)

		resp, err := session.HTTPRequest(
			ctx,
			"GET",
			"https://api.passivetotal.org/v2/enrichment/subdomains",
			"",
			map[string]string{"Content-Type": "application/json"},
			bytes.NewBuffer(request),
			subscraping.BasicAuth{Username: randomApiKey.Username, Password: randomApiKey.Password},
		)
		if err != nil {
			results <- subscraping.Result{Source: p.Name(), Type: subscraping.Error, Error: err}
			p.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var data response
		err = jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			results <- subscraping.Result{Source: p.Name(), Type: subscraping.Error, Error: err}
			p.Errors++
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		for _, subdomain := range data.Subdomains {
			// skip entries like xxx.xxx.xxx.xxx\032domain.tld
			if passiveTotalFilterRegex.MatchString(subdomain) {
				continue
			}
			finalSubdomain := subdomain + "." + domain
			results <- subscraping.Result{Source: p.Name(), Type: subscraping.Subdomain, Value: finalSubdomain}
			p.Results++
		}
	}()

	return results
}

// Name returns the name of the source
func (p *PassiveTotal) Name() string {
	return "passivetotal"
}

func (p *PassiveTotal) IsDefault() bool {
	return true
}

func (p *PassiveTotal) HasRecursiveSupport() bool {
	return true
}

func (p *PassiveTotal) SourceType() string {
	return subscraping.TYPE_API
}
