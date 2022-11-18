// Package dnsdb logic
package dnsdb

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type dnsdbResponse struct {
	Name string `json:"rrname"`
}

// DnsDB is the KeyApiSource that handles access to the DnsDB data source.
type DnsDB struct {
	*subscraping.KeyApiSource
}

func NewDnsDB() *DnsDB {
	return &DnsDB{KeyApiSource: &subscraping.KeyApiSource{}}
}

// Run function returns all subdomains found with the service
func (d *DnsDB) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(d.ApiKeys(), d.Name())
		if randomApiKey == "" {
			return
		}

		headers := map[string]string{
			"X-API-KEY":    randomApiKey,
			"Accept":       "application/json",
			"Content-Type": "application/json",
		}

		resp, err := session.Get(ctx, fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/*.%s?limit=1000000000000", domain), "", headers)
		if err != nil {
			results <- subscraping.Result{Source: d.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			var response dnsdbResponse
			err = jsoniter.NewDecoder(bytes.NewBufferString(line)).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: d.Name(), Type: subscraping.Error, Error: err}
				return
			}
			results <- subscraping.Result{Source: d.Name(), Type: subscraping.Subdomain, Value: strings.TrimSuffix(response.Name, ".")}
		}
		resp.Body.Close()
	}()
	return results
}

// Name returns the name of the source
func (d *DnsDB) Name() string {
	return "dnsdb"
}

func (d *DnsDB) SourceType() string {
	return subscraping.TYPE_API
}
