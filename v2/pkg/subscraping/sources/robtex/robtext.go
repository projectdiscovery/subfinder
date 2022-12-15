// Package robtex logic
package robtex

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	addrRecord     = "A"
	iPv6AddrRecord = "AAAA"
	baseURL        = "https://proapi.robtex.com/pdns"
)

type result struct {
	Rrname string `json:"rrname"`
	Rrdata string `json:"rrdata"`
	Rrtype string `json:"rrtype"`
}

// Robtex is the KeyApiSource that handles access to the Robtex data source.
type Robtex struct {
	*subscraping.KeyApiSource
}

func NewRobtex() *Robtex {
	return &Robtex{
		KeyApiSource: &subscraping.KeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

// Run function returns all subdomains found with the service
func (r *Robtex) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			r.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(r.ApiKeys(), r.Name())
		if randomApiKey == "" {
			r.Skipped = true
			return
		}

		headers := map[string]string{"Content-Type": "application/x-ndjson"}

		ips, err := enumerate(ctx, session, fmt.Sprintf("%s/forward/%s?key=%s", baseURL, domain, randomApiKey), headers)
		if err != nil {
			results <- subscraping.Result{Source: r.Name(), Type: subscraping.Error, Error: err}
			r.Errors++
			return
		}

		for _, result := range ips {
			if result.Rrtype == addrRecord || result.Rrtype == iPv6AddrRecord {
				domains, err := enumerate(ctx, session, fmt.Sprintf("%s/reverse/%s?key=%s", baseURL, result.Rrdata, randomApiKey), headers)
				if err != nil {
					results <- subscraping.Result{Source: r.Name(), Type: subscraping.Error, Error: err}
					r.Errors++
					return
				}
				for _, result := range domains {
					results <- subscraping.Result{Source: r.Name(), Type: subscraping.Subdomain, Value: result.Rrdata}
					r.Results++
				}
			}
		}
	}()

	return results
}

func enumerate(ctx context.Context, session *subscraping.Session, targetURL string, headers map[string]string) ([]result, error) {
	var results []result

	resp, err := session.Get(ctx, targetURL, "", headers)
	if err != nil {
		session.DiscardHTTPResponse(resp)
		return results, err
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var response result
		err = jsoniter.NewDecoder(bytes.NewBufferString(line)).Decode(&response)
		if err != nil {
			return results, err
		}

		results = append(results, response)
	}

	resp.Body.Close()

	return results, nil
}

// Name returns the name of the source
func (r *Robtex) Name() string {
	return "robtex"
}

func (r *Robtex) IsDefault() bool {
	return true
}

func (r *Robtex) SourceType() string {
	return subscraping.TYPE_API
}
