// Package bufferover is a bufferover Scraping Engine in Golang
package bufferover

import (
	"context"
	"fmt"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Meta struct {
		Errors []string `json:"Errors"`
	} `json:"Meta"`
	FDNSA   []string `json:"FDNS_A"`
	RDNS    []string `json:"RDNS"`
	Results []string `json:"Results"`
}

// BufferOver is the KeyApiSource that handles access to the BufferOver data source.
type BufferOver struct {
	*subscraping.KeyApiSource
}

func NewBufferOver() *BufferOver {
	return &BufferOver{KeyApiSource: &subscraping.KeyApiSource{Source: &subscraping.Source{Errors: 0, Results: 0}}}
}

// Run function returns all subdomains found with the service
func (b *BufferOver) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			b.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(b.ApiKeys(), b.Name())
		if randomApiKey == "" {
			b.Skipped = true
			return
		}

		b.getData(ctx, fmt.Sprintf("https://tls.bufferover.run/dns?q=.%s", domain), randomApiKey, session, results)
	}()

	return results
}

func (b *BufferOver) getData(ctx context.Context, sourceURL string, apiKey string, session *subscraping.Session, results chan subscraping.Result) {
	resp, err := session.Get(ctx, sourceURL, "", map[string]string{"x-api-key": apiKey})

	if err != nil && resp == nil {
		results <- subscraping.Result{Source: b.Name(), Type: subscraping.Error, Error: err}
		b.Errors++
		session.DiscardHTTPResponse(resp)
		return
	}

	var bufforesponse response
	err = jsoniter.NewDecoder(resp.Body).Decode(&bufforesponse)
	if err != nil {
		results <- subscraping.Result{Source: b.Name(), Type: subscraping.Error, Error: err}
		b.Errors++
		resp.Body.Close()
		return
	}

	resp.Body.Close()

	metaErrors := bufforesponse.Meta.Errors

	if len(metaErrors) > 0 {
		results <- subscraping.Result{
			Source: b.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", strings.Join(metaErrors, ", ")),
		}
		b.Errors++
		return
	}

	var subdomains []string

	if len(bufforesponse.FDNSA) > 0 {
		subdomains = bufforesponse.FDNSA
		subdomains = append(subdomains, bufforesponse.RDNS...)
	} else if len(bufforesponse.Results) > 0 {
		subdomains = bufforesponse.Results
	}

	for _, subdomain := range subdomains {
		for _, value := range session.Extractor.FindAllString(subdomain, -1) {
			results <- subscraping.Result{Source: b.Name(), Type: subscraping.Subdomain, Value: value}
		}
		b.Results++
	}
}

// Name returns the name of the source
func (b *BufferOver) Name() string {
	return "bufferover"
}

func (b *BufferOver) IsDefault() bool {
	return true
}

func (b *BufferOver) HasRecursiveSupport() bool {
	return true
}

func (b *BufferOver) SourceType() string {
	return subscraping.TYPE_API
}
