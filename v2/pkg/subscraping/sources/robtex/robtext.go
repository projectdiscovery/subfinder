// Package robtex logic
package robtex

import (
	"bufio"
	"bytes"
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	addrRecord     = "A"
	iPv6AddrRecord = "AAAA"
	baseURL        = "https://proapi.robtex.com/pdns"
)

// Source is the passive scraping agent
type Source struct{}

type result struct {
	Rrname string `json:"rrname"`
	Rrdata string `json:"rrdata"`
	Rrtype string `json:"rrtype"`
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.Robtex == "" {
			return
		}

		headers := map[string]string{"Content-Type": "application/x-ndjson"}

		ips, err := enumerate(ctx, session, fmt.Sprintf("%s/forward/%s?key=%s", baseURL, domain, session.Keys.Robtex), headers)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		for _, result := range ips {
			if result.Rrtype == addrRecord || result.Rrtype == iPv6AddrRecord {
				domains, err := enumerate(ctx, session, fmt.Sprintf("%s/reverse/%s?key=%s", baseURL, result.Rrdata, session.Keys.Robtex), headers)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					return
				}
				for _, result := range domains {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: result.Rrdata}
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
func (s *Source) Name() string {
	return "robtex"
}
