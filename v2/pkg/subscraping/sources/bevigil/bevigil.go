// Package bevigil logic
package bevigil

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Response struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
}

// Bevigil is the KeyApiSource that handles access to the Bevigil data source.
type Bevigil struct {
	*subscraping.KeyApiSource
}

func NewBevigil() *Bevigil {
	return &Bevigil{KeyApiSource: &subscraping.KeyApiSource{Source: &subscraping.Source{Errors: 0, Results: 0}}}
}

func (b *Bevigil) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			b.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(b.ApiKeys(), b.Name())
		if randomApiKey == "" {
			b.Skipped = true
			return
		}

		getUrl := fmt.Sprintf("https://osint.bevigil.com/api/%s/subdomains/", domain)

		resp, err := session.Get(ctx, getUrl, "", map[string]string{
			"X-Access-Token": randomApiKey, "User-Agent": "subfinder",
		})
		if err != nil {
			results <- subscraping.Result{Source: b.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var subdomains []string
		var response Response
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: b.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		if len(response.Subdomains) > 0 {
			subdomains = response.Subdomains
		}

		for _, subdomain := range subdomains {
			results <- subscraping.Result{Source: b.Name(), Type: subscraping.Subdomain, Value: subdomain}
		}

	}()
	return results
}

func (b *Bevigil) Name() string {
	return "bevigil"
}

func (b *Bevigil) IsDefault() bool {
	return true
}

func (b *Bevigil) SourceType() string {
	return subscraping.TYPE_API
}
