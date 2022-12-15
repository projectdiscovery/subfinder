// Package quake logic
package quake

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type quakeResults struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Service struct {
			HTTP struct {
				Host string `json:"host"`
			} `json:"http"`
		}
	} `json:"data"`
	Meta struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
}

// Quake is the KeyApiSource that handles access to the Quake data source.
type Quake struct {
	*subscraping.KeyApiSource
}

func NewQuake() *Quake {
	return &Quake{
		KeyApiSource: &subscraping.KeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

// Run function returns all subdomains found with the service
func (q *Quake) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			q.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(q.ApiKeys(), q.Name())
		if randomApiKey == "" {
			q.Skipped = true
			return
		}

		// quake api doc https://quake.360.cn/quake/#/help
		var requestBody = []byte(fmt.Sprintf(`{"query":"domain: *.%s", "start":0, "size":500}`, domain))
		resp, err := session.Post(ctx, "https://quake.360.cn/api/v3/search/quake_service", "", map[string]string{
			"Content-Type": "application/json", "X-QuakeToken": randomApiKey,
		}, bytes.NewReader(requestBody))
		if err != nil {
			results <- subscraping.Result{Source: q.Name(), Type: subscraping.Error, Error: err}
			q.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var response quakeResults
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: q.Name(), Type: subscraping.Error, Error: err}
			q.Errors++
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if response.Code != 0 {
			results <- subscraping.Result{
				Source: q.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.Message),
			}
			q.Errors++
			return
		}

		if response.Meta.Pagination.Total > 0 {
			for _, quakeDomain := range response.Data {
				subdomain := quakeDomain.Service.HTTP.Host
				if strings.ContainsAny(subdomain, "暂无权限") {
					subdomain = ""
				}
				results <- subscraping.Result{Source: q.Name(), Type: subscraping.Subdomain, Value: subdomain}
				q.Results++
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (q *Quake) Name() string {
	return "quake"
}

func (q *Quake) IsDefault() bool {
	return true
}

func (q *Quake) SourceType() string {
	return subscraping.TYPE_API
}
