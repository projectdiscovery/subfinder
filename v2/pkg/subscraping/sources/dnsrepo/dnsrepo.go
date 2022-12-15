package dnsrepo

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// DnsRepo is the KeyApiSource that handles access to the DnsRepo data source.
type DnsRepo struct {
	*subscraping.KeyApiSource
}

func NewDnsRepo() *DnsRepo {
	return &DnsRepo{
		KeyApiSource: &subscraping.KeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

type DnsRepoResponse []struct {
	Domain string
}

func (d *DnsRepo) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			d.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(d.ApiKeys(), d.Name())
		if randomApiKey == "" {
			d.Skipped = true
			return
		}
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://dnsrepo.noc.org/api/?apikey=%s&search=%s", randomApiKey, domain))
		if err != nil {
			results <- subscraping.Result{Source: d.Name(), Type: subscraping.Error, Error: err}
			d.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}
		responseData, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: d.Name(), Type: subscraping.Error, Error: err}
			d.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}
		resp.Body.Close()
		var result DnsRepoResponse
		err = jsoniter.Unmarshal(responseData, &result)
		if err != nil {
			results <- subscraping.Result{Source: d.Name(), Type: subscraping.Error, Error: err}
			d.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}
		for _, sub := range result {
			results <- subscraping.Result{
				Source: d.Name(), Type: subscraping.Subdomain, Value: strings.TrimSuffix(sub.Domain, "."),
			}
			d.Results++
		}

	}()

	return results
}

// Name returns the name of the source
func (d *DnsRepo) Name() string {
	return "dnsrepo"
}

func (d *DnsRepo) IsDefault() bool {
	return true
}

func (d *DnsRepo) SourceType() string {
	return subscraping.TYPE_API
}
