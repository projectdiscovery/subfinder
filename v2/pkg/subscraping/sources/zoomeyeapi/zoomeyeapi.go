package zoomeyeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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

// ZoomEyeApi is the KeyApiSource that handles access to the ZoomEyeApi data source.
type ZoomEyeApi struct {
	*subscraping.KeyApiSource
}

func NewZoomEyeApi() *ZoomEyeApi {
	return &ZoomEyeApi{
		KeyApiSource: &subscraping.KeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

// Run function returns all subdomains found with the service
func (z *ZoomEyeApi) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			z.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(z.ApiKeys(), z.Name())
		if randomApiKey == "" {
			z.Skipped = true
			return
		}

		headers := map[string]string{
			"API-KEY":      randomApiKey,
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
					results <- subscraping.Result{Source: z.Name(), Type: subscraping.Error, Error: err}
					z.Errors++
					session.DiscardHTTPResponse(resp)
				}
				return
			}

			var res zoomeyeResults
			err = json.NewDecoder(resp.Body).Decode(&res)

			if err != nil {
				results <- subscraping.Result{Source: z.Name(), Type: subscraping.Error, Error: err}
				z.Errors++
				_ = resp.Body.Close()
				return
			}
			_ = resp.Body.Close()
			pages = int(res.Total/1000) + 1
			for _, r := range res.List {
				results <- subscraping.Result{Source: z.Name(), Type: subscraping.Subdomain, Value: r.Name}
				z.Results++
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (z *ZoomEyeApi) Name() string {
	return "zoomeyeapi"
}

func (z *ZoomEyeApi) SourceType() string {
	return subscraping.TYPE_API
}
