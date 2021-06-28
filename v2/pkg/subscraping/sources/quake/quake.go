// Package quake logic
package quake

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type quakeResults struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Service struct {
			HTTP struct {
				// Title           string `json:"title"`
				Host string `json:"host"`
				// StatusCode int    `json:"status_code"`
				// ResponseHeaders string `json:"response_headers"`
			} `json:"http"`
		}
	}
	Meta struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)

		if session.Keys.Quake == "" {
			return
		}

		// quake api doc https://quake.360.cn/quake/#/help
		var requestBody = []byte(`{"query":"domain: *.` + domain + `", "start":0, "size":1000}`)
		resp, err := session.Post(ctx, "https://quake.360.cn/api/v3/search/quake_service", "", map[string]string{"Content-Type": "application/json", "X-QuakeToken": session.Keys.Quake}, bytes.NewReader(requestBody))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response quakeResults
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if response.Code != 0 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.Message)}
			return
		}

		if response.Meta.Pagination.Total > 0 {
			for _, quakeDomain := range response.Data {
				subdomain := quakeDomain.Service.HTTP.Host
				if strings.ContainsAny(subdomain, "暂无权限") {
					subdomain = ""
				}
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "quake"
}
