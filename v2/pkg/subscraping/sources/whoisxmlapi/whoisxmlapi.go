// Package whoisxmlapi logic
package whoisxmlapi

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Search string `json:"search"`
	Result Result `json:"result"`
}

type Result struct {
	Count   int      `json:"count"`
	Records []Record `json:"records"`
}

type Record struct {
	Domain    string `json:"domain"`
	FirstSeen int    `json:"firstSeen"`
	LastSeen  int    `json:"lastSeen"`
}

// WhoIsXmlApi is the KeyApiSource that handles access to the WhoIsXmlApi data source.
type WhoIsXmlApi struct {
	*subscraping.KeyApiSource
}

func NewWhoIsXmlApi() *WhoIsXmlApi {
	return &WhoIsXmlApi{
		KeyApiSource: &subscraping.KeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

// Run function returns all subdomains found with the service
func (w *WhoIsXmlApi) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			w.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(w.ApiKeys(), w.Name())
		if randomApiKey == "" {
			w.Skipped = true
			return
		}

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://subdomains.whoisxmlapi.com/api/v1?apiKey=%s&domainName=%s", randomApiKey, domain))
		if err != nil {
			results <- subscraping.Result{Source: w.Name(), Type: subscraping.Error, Error: err}
			w.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var data response
		err = jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			results <- subscraping.Result{Source: w.Name(), Type: subscraping.Error, Error: err}
			w.Errors++
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		for _, record := range data.Result.Records {
			results <- subscraping.Result{Source: w.Name(), Type: subscraping.Subdomain, Value: record.Domain}
			w.Results++
		}
	}()

	return results
}

// Name returns the name of the source
func (w *WhoIsXmlApi) Name() string {
	return "whoisxmlapi"
}

func (w *WhoIsXmlApi) IsDefault() bool {
	return true
}

func (w *WhoIsXmlApi) SourceType() string {
	return subscraping.TYPE_API
}
