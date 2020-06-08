package intelx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
	"io/ioutil"
	"net/http"
)

type searchResponseType struct {
	Id     string `json:"id"`
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

type Source struct{}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {

	results := make(chan subscraping.Result)

	go func() {
		if session.Keys.IntelXKey == "" || session.Keys.IntelXHost == "" {
			fmt.Println(session.Keys)
			close(results)
			return
		}

		search_url := fmt.Sprintf("https://%s/phonebook/search?k=%s", session.Keys.IntelXHost, session.Keys.IntelXKey)

		reqBody := requestBody{
			Term:       domain,
			Maxresults: 100000,
			Media:      0,
			Target:     1,
			Timeout:    20,
		}

		body, err := json.Marshal(reqBody)

		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		resp, err := http.Post(search_url, "application/json", bytes.NewBuffer(body))

		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		var response searchResponseType

		err = jsoniter.NewDecoder(resp.Body).Decode(&response)

		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		results_url := fmt.Sprintf("https://%s/phonebook/search/result?k=%s&id=%s&limit=10000", session.Keys.IntelXHost, session.Keys.IntelXKey, response.Id)

		var status = 0

		for status == 0 || status == 3 {

			resp, err = session.Get(ctx, results_url, "", map[string]string{})
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				close(results)
				return
			}
			var response searchResultType
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				close(results)
				return
			}

			body, err = ioutil.ReadAll(resp.Body)

			status = response.Status

			for _, hostname := range response.Selectors {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: hostname.Selectvalue}

			}

		}

		close(results)
	}()

	return results
}

func (s *Source) Name() string {
	return "intelx"
}
