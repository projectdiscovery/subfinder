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

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

type result struct {
	Rrname string `json:"rrname"`
	Rrdata string `json:"rrdata"`
	Rrtype string `json:"rrtype"`
}

// Run function returns all subdomains found with the service
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

		headers := map[string]string{"Content-Type": "application/x-ndjson"}

		ips, err := enumerate(ctx, session, fmt.Sprintf("%s/forward/%s?key=%s", baseURL, domain, randomApiKey), headers)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		for _, result := range ips {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if result.Rrtype == addrRecord || result.Rrtype == iPv6AddrRecord {
				domains, err := enumerate(ctx, session, fmt.Sprintf("%s/reverse/%s?key=%s", baseURL, result.Rrdata, randomApiKey), headers)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
					return
				}
				for _, result := range domains {
					select {
					case <-ctx.Done():
						return
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: result.Rrdata}:
						s.results++
					}
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

	defer session.DiscardHTTPResponse(resp)

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

	return results, nil
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "robtex"
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
