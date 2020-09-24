package cebaidu

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

type domain struct {
	Domain string `json:"domain"`
}

type cebaiduResponse struct {
	Code    int64    `json:"code"`
	Message string   `json:"message"`
	Data    []domain `json:"data"`
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://ce.baidu.com/index/getRelatedSites?site_address=%s", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response cebaiduResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if response.Code > 0 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%d, %s", response.Code, response.Message)}
			return
		}

		for _, result := range response.Data {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: result.Domain}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "cebaidu"
}
