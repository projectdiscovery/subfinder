// Package virustotal logic
package virustotal

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Subdomains []string `json:"subdomains"`
}

// VirusTotal is the KeyApiSource that handles access to the VirusTotal data source.
type VirusTotal struct {
	*subscraping.KeyApiSource
}

func NewVirusTotal() *VirusTotal {
	return &VirusTotal{
		KeyApiSource: &subscraping.KeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

// Run function returns all subdomains found with the service
func (v *VirusTotal) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			v.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(v.ApiKeys(), v.Name())
		if randomApiKey == "" {
			return
		}

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", randomApiKey, domain))
		if err != nil {
			results <- subscraping.Result{Source: v.Name(), Type: subscraping.Error, Error: err}
			v.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var data response
		err = jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			results <- subscraping.Result{Source: v.Name(), Type: subscraping.Error, Error: err}
			v.Errors++
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		for _, subdomain := range data.Subdomains {
			results <- subscraping.Result{Source: v.Name(), Type: subscraping.Subdomain, Value: subdomain}
			v.Results++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *VirusTotal) Name() string {
	return "virustotal"
}

func (s *VirusTotal) IsDefault() bool {
	return true
}

func (s *VirusTotal) HasRecursiveSupport() bool {
	return true
}

func (v *VirusTotal) SourceType() string {
	return subscraping.TYPE_API
}
