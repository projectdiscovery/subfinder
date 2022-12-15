// Package chaos logic
package chaos

import (
	"context"
	"fmt"
	"time"

	"github.com/projectdiscovery/chaos-client/pkg/chaos"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Chaos is the KeyApiSource that handles access to the Chaos data source.
type Chaos struct {
	*subscraping.KeyApiSource
}

func NewChaos() *Chaos {
	return &Chaos{
		KeyApiSource: &subscraping.KeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

// Run function returns all subdomains found with the service
func (c *Chaos) Run(_ context.Context, domain string, _ *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			c.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(c.ApiKeys(), c.Name())
		if randomApiKey == "" {
			c.Skipped = true
			return
		}

		chaosClient := chaos.New(randomApiKey)
		for result := range chaosClient.GetSubdomains(&chaos.SubdomainsRequest{
			Domain: domain,
		}) {
			if result.Error != nil {
				results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: result.Error}
				c.Errors++
				break
			}
			results <- subscraping.Result{
				Source: c.Name(), Type: subscraping.Subdomain, Value: fmt.Sprintf("%s.%s", result.Subdomain, domain),
			}
			c.Results++
		}
	}()

	return results
}

// Name returns the name of the source
func (c *Chaos) Name() string {
	return "chaos"
}

func (c *Chaos) IsDefault() bool {
	return true
}

func (c *Chaos) SourceType() string {
	return subscraping.TYPE_API
}
