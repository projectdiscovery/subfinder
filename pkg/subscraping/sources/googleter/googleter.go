package googleter

import (
	"context"
	"io/ioutil"
	"net/url"
	"regexp"
	"strconv"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

var (
	metaRegex  = regexp.MustCompile(`\[null,"(.*)",null,(.*),(.*)]`)
	metaRegex2 = regexp.MustCompile(`\["(.*)",".*",null,(.*),(.*)]`)
)

type agent struct {
	subdomains chan subscraping.Result
	session    *subscraping.Session
}

func (a *agent) makeRequest(token string, domain string) (string, error) {
	requestURI := ""

	if token == "" {
		requestURI = "https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?domain=" + url.QueryEscape(domain) + "&include_expired=true&include_subdomains=true"
	} else {
		requestURI = "https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch/page?domain=" + url.QueryEscape(domain) + "&include_expired=true&include_subdomains=true&p=" + url.QueryEscape(token)
	}

	resp, err := a.session.Get(requestURI, "", map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36",
		"Referer":    "https://transparencyreport.google.com/https/certificates",
	})
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		return "", err
	}
	resp.Body.Close()

	return string(body), nil
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	a := agent{
		session:    session,
		subdomains: results,
	}

	go func() {
		respBody, err := a.makeRequest("", domain)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		var Token string

		matches := metaRegex.FindStringSubmatch(string(respBody))
		if len(matches) <= 1 {
			close(results)
			return
		}

		for _, sub := range session.Extractor.FindAllString(respBody, -1) {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: sub}
		}

		Token = matches[1]
		MaxPages, _ := strconv.Atoi(matches[3])
		for i := 1; i <= MaxPages; i++ {
			further := a.getSubdomains(ctx, &Token, domain, session, s, results)
			if !further {
				break
			}
		}
		close(results)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "googleter"
}

func (a *agent) getSubdomains(ctx context.Context, Token *string, domain string, session *subscraping.Session, s *Source, results chan subscraping.Result) bool {
	respBody, err := a.makeRequest(*Token, domain)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		return false
	}
	for _, sub := range session.Extractor.FindAllString(respBody, -1) {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: sub}
	}

	matches := metaRegex2.FindStringSubmatch(respBody)
	matches2 := metaRegex.FindStringSubmatch(respBody)
	if len(matches2) > 1 {
		*Token = matches2[1]
	}
	if len(matches) > 1 {
		*Token = matches[1]
	}
	return true
}
