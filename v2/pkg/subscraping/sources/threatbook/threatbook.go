// Package threatbook logic
package threatbook

import (
	"context"
	"fmt"
	"strconv"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type threatBookResponse struct {
	ResponseCode int64  `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
	Data         struct {
		Domain     string `json:"domain"`
		SubDomains struct {
			Total string   `json:"total"`
			Data  []string `json:"data"`
		} `json:"sub_domains"`
	} `json:"data"`
}

// ThreatBook is the KeyApiSource that handles access to the ThreatBook data source.
type ThreatBook struct {
	*subscraping.KeyApiSource
}

func NewThreatBook() *ThreatBook {
	return &ThreatBook{KeyApiSource: &subscraping.KeyApiSource{}}
}

// Run function returns all subdomains found with the service
func (t *ThreatBook) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(t.ApiKeys(), t.Name())
		if randomApiKey == "" {
			return
		}

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://api.threatbook.cn/v3/domain/sub_domains?apikey=%s&resource=%s", randomApiKey, domain))
		if err != nil && resp == nil {
			results <- subscraping.Result{Source: t.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response threatBookResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: t.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if response.ResponseCode != 0 {
			results <- subscraping.Result{Source: t.Name(), Type: subscraping.Error, Error: fmt.Errorf("code %d, %s", response.ResponseCode, response.VerboseMsg)}
			return
		}

		total, err := strconv.ParseInt(response.Data.SubDomains.Total, 10, 64)
		if err != nil {
			results <- subscraping.Result{Source: t.Name(), Type: subscraping.Error, Error: err}
			return
		}

		if total > 0 {
			for _, subdomain := range response.Data.SubDomains.Data {
				results <- subscraping.Result{Source: t.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (t *ThreatBook) Name() string {
	return "threatbook"
}

func (t *ThreatBook) SourceType() string {
	return subscraping.TYPE_API
}
