// Package sitedossier logic
package sitedossier

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// SleepRandIntn is the integer value to get the pseudo-random number
// to sleep before find the next match
const SleepRandIntn = 5

var reNext = regexp.MustCompile(`<a href="([A-Za-z0-9/.]+)"><b>`)

type agent struct {
	results chan subscraping.Result
	session *subscraping.Session
}

func (a *agent) enumerate(ctx context.Context, baseURL string) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := a.session.SimpleGet(ctx, baseURL)
	isnotfound := resp != nil && resp.StatusCode == http.StatusNotFound
	if err != nil && !isnotfound {
		a.results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
		a.session.DiscardHTTPResponse(resp)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		a.results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
		resp.Body.Close()
		return
	}
	resp.Body.Close()

	src := string(body)
	for _, match := range a.session.Extractor.FindAllString(src, -1) {
		a.results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Subdomain, Value: match}
	}

	match1 := reNext.FindStringSubmatch(src)
	time.Sleep(time.Duration((3 + rand.Intn(SleepRandIntn))) * time.Second)

	if len(match1) > 0 {
		a.enumerate(ctx, "http://www.sitedossier.com"+match1[1])
	}
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	a := agent{
		session: session,
		results: results,
	}

	go func() {
		a.enumerate(ctx, fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain))
		close(a.results)
	}()

	return a.results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "sitedossier"
}
