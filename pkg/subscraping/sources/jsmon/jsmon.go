// Package jsmon logic
package jsmon

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	baseUrl = "https://api.jsmon.sh"
)

type subdomainsResponse struct {
	Subdomains []string `json:"subdomains"`
	Status     string   `json:"status"`
	Message    string   `json:"message"`
}

type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		randomApiInfo := strings.Split(randomApiKey, ":")
		if len(randomApiInfo) != 2 {
			s.skipped = true
			return
		}

		authToken := randomApiInfo[0]
		wkspId := randomApiInfo[1]

		subfinderScanURL := fmt.Sprintf("%s/api/v2/subfinderScan2?wkspId=%s", baseUrl, wkspId)
		requestBody := fmt.Sprintf(`{"domain":"%s"}`, domain)
		headers := map[string]string{
			"X-Jsmon-Key":  authToken,
			"Content-Type": "application/json",
		}

		resp, err := session.Post(ctx, subfinderScanURL, "", headers, bytes.NewReader([]byte(requestBody)))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("subfinderScan API returned status %d: %s", resp.StatusCode, string(body))}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var response subdomainsResponse
		if err := jsoniter.NewDecoder(resp.Body).Decode(&response); err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		session.DiscardHTTPResponse(resp)

		for _, subdomain := range response.Subdomains {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			s.results++
		}

	}()

	return results
}

func (s *Source) Name() string {
	return "jsmon"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
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
