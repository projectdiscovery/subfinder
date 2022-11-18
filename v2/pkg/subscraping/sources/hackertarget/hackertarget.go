// Package hackertarget logic
package hackertarget

import (
	"bufio"
	"context"
	"fmt"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// HackerTarget is the Source that handles access to the HackerTarget data source.
type HackerTarget struct {
	*subscraping.Source
}

func NewHackerTarget() *HackerTarget {
	return &HackerTarget{Source: &subscraping.Source{}}
}

// Run function returns all subdomains found with the service
func (h *HackerTarget) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("http://api.hackertarget.com/hostsearch/?q=%s", domain))
		if err != nil {
			results <- subscraping.Result{Source: h.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			match := session.Extractor.FindAllString(line, -1)
			for _, subdomain := range match {
				results <- subscraping.Result{Source: h.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (h *HackerTarget) Name() string {
	return "hackertarget"
}

func (h *HackerTarget) IsDefault() bool {
	return true
}

func (h *HackerTarget) HasRecursiveSupport() bool {
	return true
}

func (h *HackerTarget) SourceType() string {
	return subscraping.TYPE_API
}
