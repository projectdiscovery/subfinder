// Package intelx logic
package intelx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type searchResponseType struct {
	ID     string `json:"id"`
	Status int    `json:"status"`
}

type selectorType struct {
	Selectvalue string `json:"selectorvalue"`
}

type searchResultType struct {
	Selectors []selectorType `json:"selectors"`
	Status    int            `json:"status"`
}

type requestBody struct {
	Term       string
	Maxresults int
	Media      int
	Target     int
	Terminate  []int
	Timeout    int
}

// IntelX is the CredsApiSource that handles access to the IntelX data source.
type IntelX struct {
	*subscraping.MultiPartKeyApiSource
}

func NewIntelX() *IntelX {
	return &IntelX{MultiPartKeyApiSource: &subscraping.MultiPartKeyApiSource{}}
}

// Run function returns all subdomains found with the service
func (i *IntelX) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(i.ApiKeys(), i.Name())
		if randomApiKey.Username == "" || randomApiKey.Password == "" {
			return
		}

		searchURL := fmt.Sprintf("https://%s/phonebook/search?k=%s", randomApiKey.Username, randomApiKey.Password)
		reqBody := requestBody{
			Term:       domain,
			Maxresults: 100000,
			Media:      0,
			Target:     1,
			Timeout:    20,
		}

		body, err := json.Marshal(reqBody)
		if err != nil {
			results <- subscraping.Result{Source: i.Name(), Type: subscraping.Error, Error: err}
			return
		}

		resp, err := session.SimplePost(ctx, searchURL, "application/json", bytes.NewBuffer(body))
		if err != nil {
			results <- subscraping.Result{Source: i.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response searchResponseType
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: i.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		resultsURL := fmt.Sprintf("https://%s/phonebook/search/result?k=%s&id=%s&limit=10000", randomApiKey.Username, randomApiKey.Password, response.ID)
		status := 0
		for status == 0 || status == 3 {
			resp, err = session.Get(ctx, resultsURL, "", nil)
			if err != nil {
				results <- subscraping.Result{Source: i.Name(), Type: subscraping.Error, Error: err}
				session.DiscardHTTPResponse(resp)
				return
			}
			var response searchResultType
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: i.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return
			}

			_, err = io.ReadAll(resp.Body)
			if err != nil {
				results <- subscraping.Result{Source: i.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			status = response.Status
			for _, hostname := range response.Selectors {
				results <- subscraping.Result{Source: i.Name(), Type: subscraping.Subdomain, Value: hostname.Selectvalue}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (i *IntelX) Name() string {
	return "intelx"
}

func (i *IntelX) IsDefault() bool {
	return true
}

func (i *IntelX) SourceType() string {
	return subscraping.TYPE_API
}
