package dnsrepo

import (
	"context"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

var reNext = regexp.MustCompile(`<a href=[\"\'](\/\?domain=)[\"\']*.*>(<]+|.*?)?<\/a>`)
var reSubNext = regexp.MustCompile(`[\"\'](\/\?domain=)\w+.*[\"\']`)

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://dnsrepo.noc.org/?search=%s", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}
		responseData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}
		resp.Body.Close()
		src := string(responseData)
		for _, match := range reNext.FindAllStringSubmatch(src, len(src)) {
			for _, subMatch := range reSubNext.FindAllStringSubmatch(match[0], len(match[0])) {
				splt := strings.Split(subMatch[0], "=")[1]
				splt = strings.Trim(splt, `".`)
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: splt}
			}
		}

	}()
	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "dnsrepo"
}
