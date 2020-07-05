// GitHub search package, based on gwen001's https://github.com/gwen001/github-search github-subdomains
package github

import (
	"context"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"net/url"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
	"github.com/tomnomnom/linkheader"
)

type item struct {
	Name    string `json:"name"`
	HtmlUrl string `json:"html_url"`
}

type response struct {
	TotalCount int    `json:"total_count"`
	Items      []item `json:"items"`
}

// Source is the passive scraping agent
type Source struct{}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		if session.Keys.GitHub == "" {
			close(results)
			return
		}

		// search on GitHub with exact match
		searchURL := fmt.Sprintf("https://api.github.com/search/code?per_page=100&q=\"%s\"", domain)
		headers := map[string]string{
			"Accept":        "application/vnd.github.v3+json",
			"Authorization": "token " + session.Keys.GitHub,
		}
		s.enumerate(ctx, searchURL, headers, s.DomainRegexp(domain), session, results)
		close(results)
	}()

	return results
}

func (s *Source) enumerate(ctx context.Context, searchURL string, headers map[string]string, domainRegexp *regexp.Regexp, session *subscraping.Session, results chan subscraping.Result) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Initial request to GitHub search
	resp, err := session.Get(ctx, searchURL, "", headers)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		return
	}

	// Links header, first, next, last...
	linksHeader := linkheader.Parse(resp.Header.Get("Link"))

	data := response{}

	// Marshall json reponse
	err = jsoniter.NewDecoder(resp.Body).Decode(&data)
	resp.Body.Close()
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		return
	}

	// Response items iteration
	for _, item := range data.Items {
		resp, err := session.NormalGetWithContext(ctx, s.RawUrl(item.HtmlUrl))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		// Get the item code from the raw file url
		code, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		// Search for domain matches in the code
		domainMatch := domainRegexp.FindStringSubmatch(string(code))
		if len(domainMatch) > 0 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: domainMatch[1]}
		}
	}

	// Proccess the next link recursively
	for _, link := range linksHeader {
		if link.Rel == "next" {
			nextUrl, err := url.QueryUnescape(link.URL)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				return
			}
			gologger.Verbosef("Next URL %s\n", s.Name(), nextUrl)
			s.enumerate(ctx, nextUrl, headers, domainRegexp, session, results)
		}
	}
}

// Domain regular expression to match subdomains in github files code
func (s *Source) DomainRegexp(domain string) *regexp.Regexp {
	rdomain := strings.Replace(domain, ".", "\\.", -1)
	return regexp.MustCompile("(([0-9a-z_\\-\\.]+)\\." + rdomain + ")")
}

// Raw URL to get the files code and match for subdomains
func (s *Source) RawUrl(htmlUrl string) string {
	domain := strings.Replace(htmlUrl, "https://github.com/", "https://raw.githubusercontent.com/", -1)
	return strings.Replace(domain, "/blob/", "/", -1)
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "github"
}
