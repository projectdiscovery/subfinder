// Package threatminer logic
package threatminer

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	StatusCode    string   `json:"status_code"`
	StatusMessage string   `json:"status_message"`
	Results       []string `json:"results"`
}

// ThreatMiner is the Source that handles access to the ThreatMiner data source.
type ThreatMiner struct {
	*subscraping.Source
}

func NewThreatMiner() *ThreatMiner {
	return &ThreatMiner{Source: &subscraping.Source{}}
}

// Run function returns all subdomains found with the service
func (t *ThreatMiner) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain))
		if err != nil {
			results <- subscraping.Result{Source: t.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		defer resp.Body.Close()

		var data response
		err = jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			results <- subscraping.Result{Source: t.Name(), Type: subscraping.Error, Error: err}
			return
		}

		for _, subdomain := range data.Results {
			results <- subscraping.Result{Source: t.Name(), Type: subscraping.Subdomain, Value: subdomain}
		}
	}()

	return results
}

// Name returns the name of the source
func (t *ThreatMiner) Name() string {
	return "threatminer"
}

func (t *ThreatMiner) IsDefault() bool {
	return true
}

func (t *ThreatMiner) SourceType() string {
	return subscraping.TYPE_API
}
