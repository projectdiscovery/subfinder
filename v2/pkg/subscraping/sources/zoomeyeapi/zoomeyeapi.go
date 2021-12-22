package zoomeyeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// search results
type zoomeyeResults struct {
	Status int `json:"status"`
	Total  int `json:"total"`
	List   []struct {
		Name string   `json:"name"`
		Ip   []string `json:"ip"`
	} `json:"list"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.ZoomEyeKey == "" {
			return
		}

		headers := map[string]string{
			"API-KEY":      session.Keys.ZoomEyeKey,
			"Accept":       "application/json",
			"Content-Type": "application/json",
		}
		var pages = 1
		for currentPage := 1; currentPage <= pages; currentPage++ {
			api := fmt.Sprintf("https://api.zoomeye.org/domain/search?q=%s&type=1&s=1000&page=%d", domain, currentPage)
			resp, err := session.Get(ctx, api, "", headers)
			isForbidden := resp != nil && resp.StatusCode == http.StatusForbidden
			if err != nil {
				if !isForbidden {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					session.DiscardHTTPResponse(resp)
				}
				return
			}

			var res zoomeyeResults
			err = json.NewDecoder(resp.Body).Decode(&res)

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				_ = resp.Body.Close()
				return
			}
			_ = resp.Body.Close()
			pages = int(res.Total/1000) + 1
			for _, r := range res.List {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: r.Name}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "zoomeyeapi"
}
