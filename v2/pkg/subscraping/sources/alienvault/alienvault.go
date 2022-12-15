// Package alienvault logic
package alienvault

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type alienvaultResponse struct {
	Detail     string `json:"detail"`
	Error      string `json:"error"`
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

// AlienVault is the Source that handles access to the AlienVault data source.
type AlienVault struct {
	*subscraping.Source
}

func NewAlienVault() *AlienVault {
	return &AlienVault{Source: &subscraping.Source{Errors: 0, Results: 0}}
}

// Run function returns all subdomains found with the service
func (a *AlienVault) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			a.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain))
		if err != nil && resp == nil {
			results <- subscraping.Result{Source: a.Name(), Type: subscraping.Error, Error: err}
			a.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var response alienvaultResponse
		// Get the response body and decode
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: a.Name(), Type: subscraping.Error, Error: err}
			a.Errors++
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if response.Error != "" {
			results <- subscraping.Result{
				Source: a.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s, %s", response.Detail, response.Error),
			}
			return
		}

		for _, record := range response.PassiveDNS {
			results <- subscraping.Result{Source: a.Name(), Type: subscraping.Subdomain, Value: record.Hostname}
			a.Results++
		}
	}()

	return results
}

// Name returns the name of the source
func (a *AlienVault) Name() string {
	return "alienvault"
}

func (a *AlienVault) IsDefault() bool {
	return true
}

func (a *AlienVault) HasRecursiveSupport() bool {
	return true
}

func (a *AlienVault) SourceType() string {
	return subscraping.TYPE_API
}
