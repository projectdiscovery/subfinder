package spyse

import (
	"context"
	"strconv"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)


type resultObject struct {
	Name string `json:"name"`
}

type dataObject struct {
	Items []resultObject `json:"items"`
	Total_Count int `json:"total_count"`
}

type errorObject struct {
	Code string `json:"code"`
	Message string `json:"message"`
}


type spyseResult struct {
	Data dataObject `json:"data"`
	Error []errorObject `json:"error"`
}


type Source struct{}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		if session.Keys.Spyse == "" {
			close(results)
			return
		}

		maxCount := 100;

		for offSet := 0; offSet <= maxCount; offSet += 100 {
			resp, err := session.Get(ctx, fmt.Sprintf("https://api.spyse.com/v3/data/domain/subdomain?domain=%s&limit=100&offset=%s", domain, strconv.Itoa(offSet)), "", map[string]string{"Authorization": "Bearer " + session.Keys.Spyse})
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				session.DiscardHttpResponse(resp)
				close(results)
				return
			}


			var response spyseResult;

			err = jsoniter.NewDecoder(resp.Body).Decode(&response)

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				close(results)
				return
			}
			resp.Body.Close()

			if response.Data.Total_Count == 0 {
				close(results)
				return
			}

			maxCount = response.Data.Total_Count;

			for _, hostname := range response.Data.Items {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: hostname.Name}
			}
		}
		close(results)
	}()

	return results
}


// Name returns the name of the source
func (s *Source) Name() string {
	return "spyse"
}
