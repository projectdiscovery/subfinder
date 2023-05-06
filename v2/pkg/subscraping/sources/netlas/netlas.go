// Package netlas logic
package netlas

import (
	"context"

	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Item struct {
	Data struct {
		A           []string `json:"a,omitempty"`
		Txt         []string `json:"txt,omitempty"`
		LastUpdated string   `json:"last_updated,omitempty"`
		Timestamp   string   `json:"@timestamp,omitempty"`
		Ns          []string `json:"ns,omitempty"`
		Level       int      `json:"level,omitempty"`
		Zone        string   `json:"zone,omitempty"`
		Domain      string   `json:"domain,omitempty"`
		Cname       []string `json:"cname,omitempty"`
		Mx          []string `json:"mx,omitempty"`
	} `json:"data"`
}

type Response struct {
	Items []Item `json:"items"`
	Took  int    `json:"took"`
}

type DomainsCountResponse struct {
	Count int `json:"count"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

// func get_domains(offset string, domain string) int {

// 	return resp.StatusCode
// }

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		// To get count of domains
		endpoint := "https://app.netlas.io/api/domains_count/"
		paramss := url.Values{}
		paramss.Set("q", "domain:(domain:*."+domain+" "+"AND NOT domain:"+domain+")")
		countUrl := endpoint + "?" + paramss.Encode()

		client := &http.Client{}
		req, _ := http.NewRequest("GET", countUrl, nil)
		req.Header.Set("accept", "application/json")

		// Pick an API key
		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey != "" {
			req.Header.Set("X-API-Key", randomApiKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		} else if resp.StatusCode != 200 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("request rate limited with status code %d", resp.StatusCode)}
			s.errors++
			return
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("Error Reading ressponse body")}
			s.errors++
			return
		}

		// Parse the JSON response
		var domainsCount DomainsCountResponse
		err = json.Unmarshal(body, &domainsCount)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		//Define the API endpoint URL and query parameters

		for i := 0; i < domainsCount.Count; i += 20 {

			time.Sleep(1200 * time.Millisecond)
			offset := strconv.Itoa(i)

			endpoint := "https://app.netlas.io/api/domains/"
			params := url.Values{}
			params.Set("q", "domain:(domain:*."+domain+" "+"AND NOT domain:"+domain+")")
			params.Set("source_type", "include")
			params.Set("start", offset)
			params.Set("fields", "*")
			apiUrl := endpoint + "?" + params.Encode()

			// Send the HTTP request and read the response body
			client := &http.Client{}
			req, _ := http.NewRequest("GET", apiUrl, nil)
			req.Header.Set("accept", "application/json")

			// Pick an API key
			randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
			if randomApiKey != "" {
				req.Header.Set("X-API-Key", randomApiKey)
			}

			resp, _ := client.Do(req)
			body, _ := ioutil.ReadAll(resp.Body)

			if resp.StatusCode == 429 {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("request rate limited with status code %d", resp.StatusCode)}
				s.errors++
				break
			}

			// Parse the response body and extract the domain values
			var data Response
			json.Unmarshal(body, &data)

			for _, item := range data.Items {
				results <- subscraping.Result{
					Source: s.Name(), Type: subscraping.Subdomain, Value: item.Data.Domain,
				}
				s.results++
			}
		}

	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "netlas"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}

type subResponse struct {
	Subdomain   string    `json:"subdomain"`
	DistinctIps int       `json:"distinct_ips"`
	LastSeen    time.Time `json:"last_seen"`
}
