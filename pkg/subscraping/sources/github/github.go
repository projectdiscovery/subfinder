// Package github GitHub search package
// Based on gwen001's https://github.com/gwen001/github-search github-subdomains
package github

import (
	"context"
	"fmt"
	"io/ioutil"
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
	Name        string      `json:"name"`
	HTMLURL     string      `json:"html_url"`
	TextMatches []textMatch `json:"text_matches"`
}

type response struct {
	TotalCount int    `json:"total_count"`
	Items      []item `json:"items"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		if len(session.Keys.GitHub) == 0 {
			close(results)
			return
		}

		tokens := NewTokenManager(session.Keys.GitHub)

		// search on GitHub with exact match
		searchURL := fmt.Sprintf("https://api.github.com/search/code?per_page=100&q=\"%s\"", domain)
		s.enumerate(ctx, searchURL, s.DomainRegexp(domain), tokens, session, results)
		close(results)
	}()

	return results
}

func (s *Source) enumerate(ctx context.Context, searchURL string, domainRegexp *regexp.Regexp, tokens *Tokens, session *subscraping.Session, results chan subscraping.Result) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	token := tokens.Get()

	if token.RetryAfter > 0 {
		if len(tokens.pool) == 1 {
			gologger.Verbosef("GitHub Search request rate limit exceeded, waiting for %d seconds before retry... \n", s.Name(), token.RetryAfter)
			time.Sleep(time.Duration(token.RetryAfter) * time.Second)
		} else {
			token = tokens.Get()
		}
	}

	headers := map[string]string{
		"Accept":        "application/vnd.github.v3.text-match+json",
		"Authorization": "token " + token.Hash,
	}

	// Initial request to GitHub search
	resp, err := session.Get(ctx, searchURL, "", headers)
	isForbidden := resp != nil && resp.StatusCode == http.StatusForbidden

	if err != nil && !isForbidden {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		session.DiscardHTTPResponse(resp)
		return
	}

	// Retry enumerarion after Retry-After seconds on rate limit abuse detected
	ratelimitRemaining, _ := strconv.ParseInt(resp.Header.Get("X-Ratelimit-Remaining"), 10, 64)
	if isForbidden && ratelimitRemaining == 0 {
		retryAfterSeconds, _ := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64)
		tokens.setCurrentTokenExceeded(retryAfterSeconds)

		s.enumerate(ctx, searchURL, domainRegexp, tokens, session, results)
	} else {
		// Links header, first, next, last...
		linksHeader := linkheader.Parse(resp.Header.Get("Link"))

		data := response{}

		// Marshall json response
		err = jsoniter.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		// Response items iteration
		for _, item := range data.Items {
			resp, err := session.NormalGetWithContext(ctx, rawURL(item.HTMLURL))
			if err != nil {
				if resp != nil && resp.StatusCode != http.StatusNotFound {
					session.DiscardHTTPResponse(resp)
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					return
				}
			}

			var subdomains []string

			if resp.StatusCode == http.StatusOK {
				// Get the item code from the raw file url
				code, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					return
				}
				// Search for domain matches in the code
				subdomains = append(subdomains, matches(domainRegexp, normalizeContent(string(code)))...)
			}

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
				nextURL, err := url.QueryUnescape(link.URL)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					return
				}
				s.enumerate(ctx, nextURL, domainRegexp, tokens, session, results)
			}
		}
	}
}

// Normalize content before matching, query unescape, remove tabs and new line chars
func normalizeContent(content string) string {
	normalizedContent, _ := url.QueryUnescape(content)
	normalizedContent = strings.ReplaceAll(normalizedContent, "\\t", "")
	normalizedContent = strings.ReplaceAll(normalizedContent, "\\n", "")
	return normalizedContent
}

// Remove duplicates from string array
func unique(arr []string) []string {
	occurred := map[string]bool{}
	result := []string{}
	for e := range arr {		
		if !occurred[arr[e]] {
			occurred[arr[e]] = true
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

// Raw URL to get the files code and match for subdomains
func rawURL(htmlURL string) string {
	domain := strings.ReplaceAll(htmlURL, "https://github.com/", "https://raw.githubusercontent.com/")
	return strings.ReplaceAll(domain, "/blob/", "/")
}

// DomainRegexp regular expression to match subdomains in github files code
func (s *Source) DomainRegexp(domain string) *regexp.Regexp {
	rdomain := strings.ReplaceAll(domain, ".", "\\.")
	return regexp.MustCompile("(\\w+[.])*" + rdomain)
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "github"
}
