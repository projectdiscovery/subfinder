// Package fofa logic
package fofa

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type fofaResponse struct {
	Error   bool     `json:"error"`
	ErrMsg  string   `json:"errmsg"`
	Size    int      `json:"size"`
	Results []string `json:"results"`
}

// Fofa is the CredsKeyApiSource that handles access to the Fofa data source.
type Fofa struct {
	*subscraping.MultiPartKeyApiSource
}

func NewFofa() *Fofa {
	return &Fofa{
		MultiPartKeyApiSource: &subscraping.MultiPartKeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

// Run function returns all subdomains found with the service
func (f *Fofa) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			f.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(f.ApiKeys(), f.Name())
		if randomApiKey.Username == "" || randomApiKey.Password == "" {
			f.Skipped = true
			return
		}

		// fofa api doc https://fofa.info/static_pages/api_help
		qbase64 := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", domain)))
		resp, err := session.SimpleGet(
			ctx,
			fmt.Sprintf(
				"https://fofa.info/api/v1/search/all?full=true&fields=host&page=1&size=10000&email=%s&key=%s&qbase64=%s",
				randomApiKey.Username, randomApiKey.Password, qbase64,
			),
		)
		if err != nil && resp == nil {
			results <- subscraping.Result{Source: f.Name(), Type: subscraping.Error, Error: err}
			f.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var response fofaResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: f.Name(), Type: subscraping.Error, Error: err}
			f.Errors++
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if response.Error {
			results <- subscraping.Result{
				Source: f.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.ErrMsg),
			}
			f.Errors++
			return
		}

		if response.Size > 0 {
			for _, subdomain := range response.Results {
				if strings.HasPrefix(strings.ToLower(subdomain), "http://") || strings.HasPrefix(strings.ToLower(subdomain), "https://") {
					subdomain = subdomain[strings.Index(subdomain, "//")+2:]
				}
				results <- subscraping.Result{Source: f.Name(), Type: subscraping.Subdomain, Value: subdomain}
				f.Results++
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (f *Fofa) Name() string {
	return "fofa"
}

func (f *Fofa) IsDefault() bool {
	return true
}

func (f *Fofa) SourceType() string {
	return subscraping.TYPE_API
}
