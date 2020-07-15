// GitHub search package, based on gwen001's https://github.com/gwen001/github-search github-subdomains
package github

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
	"github.com/tomnomnom/linkheader"
)

type textMatch struct {
	Fragment string `json:"fragment"`
}

type item struct {
	Name    		string `json:"name"`
	HtmlUrl 		string `json:"html_url"`
	TextMatches []textMatch `json:"text_matches"`
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
		if len(session.Keys.GitHub) == 0 {
			close(results)
			return
		}

		rand.Seed(time.Now().UnixNano())

		// search on GitHub with exact match
		searchURL := fmt.Sprintf("https://api.github.com/search/code?per_page=100&q=\"%s\"", domain)
		s.enumerate(ctx, searchURL, s.DomainRegexp(domain), session, results)
		close(results)
	}()

	return results
}

func (s *Source) enumerate(ctx context.Context, searchURL string, domainRegexp *regexp.Regexp, session *subscraping.Session, results chan subscraping.Result) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	// auth headers with random token
	headers := map[string]string{
		"Accept":        "application/vnd.github.v3.text-match+json",
		"Authorization": "token " + session.Keys.GitHub[rand.Intn(len(session.Keys.GitHub))],
	}

	// Initial request to GitHub search
	resp, err := session.Get(ctx, searchURL, "", headers)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		return
	}

	// Retry enumerarion after Retry-After seconds on rate limit abuse detected
	ratelimitRemaining, _ := strconv.ParseInt(resp.Header.Get("X-Ratelimit-Remaining"), 10, 64)
	if resp.StatusCode == http.StatusForbidden && ratelimitRemaining == 0 {
		retryAfterSeconds, _ := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64)
		gologger.Verbosef("GitHub Search request rate limit exceeded, waiting for %d seconds before retry... \n", s.Name(), retryAfterSeconds)

		time.Sleep(time.Duration(retryAfterSeconds) * time.Second)
		s.enumerate(ctx, searchURL, domainRegexp, session, results)
	} else {
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

			var subdomains []string

			// Search for domain matches in the code

			subdomains = append(subdomains, matches(domainRegexp, normalizeContent(string(code)))...)

			// Text matches iteration per item
			for _, textMatch := range item.TextMatches {
				// Search for domain matches in the text fragment
				subdomains = append(subdomains, matches(domainRegexp, normalizeContent(textMatch.Fragment))...)
			}

			for _, subdomain := range unique(subdomains) {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
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
				s.enumerate(ctx, nextUrl, domainRegexp, session, results)
			}
		}
	}
}

// Normalize content before matching, query unescape, remove tabs and new line chars
func normalizeContent(content string) string {
	normalizedContent, _ := url.QueryUnescape(content)
	normalizedContent = strings.Replace(normalizedContent, "\\t", "", -1)
	normalizedContent = strings.Replace(normalizedContent, "\\n", "", -1)
	return normalizedContent
}

// Remove duplicates from string array
func unique(arr []string) []string {
    occured := map[string]bool{}
    result := []string{}
    for e := range arr {
        if occured[arr[e]] != true {
            occured[arr[e]] = true
            result = append(result, arr[e])
        }
    }
    return result
}

// Find matches by regular expression in any content
func matches(regexp *regexp.Regexp, content string) []string {
	var matches []string
	match := regexp.FindAllString(content, -1)
	if len(match) > 0 {
		matches = unique(match)
	}
	return matches
}

// Domain regular expression to match subdomains in github files code
func (s *Source) DomainRegexp(domain string) *regexp.Regexp {
	rdomain := strings.Replace(domain, ".", "\\.", -1)
	return regexp.MustCompile("(\\w+[.])*" + rdomain)
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
