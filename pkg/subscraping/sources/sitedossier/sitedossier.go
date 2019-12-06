package sitedossier

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"regexp"
	"time"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

var reNext = regexp.MustCompile("<a href=\"([A-Za-z0-9\\/.]+)\"><b>")

type agent struct {
	results chan subscraping.Result
	session *subscraping.Session
}

func (a *agent) enumerate(ctx context.Context, baseURL string) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			resp, err := a.session.NormalGet(baseURL)
			if err != nil {
				a.results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
				close(a.results)
				return err
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				a.results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
				resp.Body.Close()
				close(a.results)
				return err
			}
			resp.Body.Close()
			src := string(body)

			for _, match := range a.session.Extractor.FindAllString(src, -1) {
				a.results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Subdomain, Value: match}
			}

			match1 := reNext.FindStringSubmatch(src)
			time.Sleep(time.Duration((3 + rand.Intn(5))) * time.Second)

			if len(match1) > 0 {
				a.enumerate(ctx, "http://www.sitedossier.com"+match1[1])
			}
			return nil
		}
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
		err := a.enumerate(ctx, fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain))
		if err == nil {
			close(a.results)
		}
	}()
	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "sitedossier"
}
