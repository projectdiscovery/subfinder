// Package github GitHub search package
// Based on gwen001's https://github.com/gwen001/github-search github-subdomains
package github

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/tomnomnom/linkheader"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
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
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		if len(s.apiKeys) == 0 {
			gologger.Debug().Msgf("Cannot use the %s source because there was no key defined for it.", s.Name())
			s.skipped = true
			return
		}

		tokens := NewTokenManager(s.apiKeys)

		searchURL := fmt.Sprintf("https://api.github.com/search/code?per_page=100&q=%s&sort=created&order=asc", domain)
		s.enumerate(ctx, searchURL, domainRegexp(domain), tokens, session, results)
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
	headers := map[string]string{
		"Accept": "application/vnd.github.v3.text-match+json", "Authorization": "token " + token.Hash,
	}

	// Initial request to GitHub search
	resp, err := session.Get(ctx, searchURL, "", headers)
	isForbidden := resp != nil && resp.StatusCode == http.StatusForbidden
	if err != nil && !isForbidden {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		s.errors++
		session.DiscardHTTPResponse(resp)
		return
	}

	// Retry enumerarion after Retry-After seconds on rate limit abuse detected
	ratelimitRemaining, _ := strconv.ParseInt(resp.Header.Get("X-Ratelimit-Remaining"), 10, 64)
	if isForbidden && ratelimitRemaining == 0 {
		retryAfterSeconds, _ := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64)
		tokens.setCurrentTokenExceeded(retryAfterSeconds)
		session.DiscardHTTPResponse(resp)

		s.enumerate(ctx, searchURL, domainRegexp, tokens, session, results)
	}

	var data response

	// Marshall json response
	err = jsoniter.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		s.errors++
		session.DiscardHTTPResponse(resp)
		return
	}

	session.DiscardHTTPResponse(resp)

	err = s.proccesItems(ctx, data.Items, domainRegexp, s.Name(), session, results)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		s.errors++
		return
	}

	// Links header, first, next, last...
	linksHeader := linkheader.Parse(resp.Header.Get("Link"))
	// Process the next link recursively
	for _, link := range linksHeader {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if link.Rel == "next" {
			nextURL, err := url.QueryUnescape(link.URL)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				return
			}
			s.enumerate(ctx, nextURL, domainRegexp, tokens, session, results)
		}
	}
}

// proccesItems process github response items
func (s *Source) proccesItems(ctx context.Context, items []item, domainRegexp *regexp.Regexp, name string, session *subscraping.Session, results chan subscraping.Result) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(items))

	for _, responseItem := range items {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		wg.Add(1)
		go func(responseItem item) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			resp, err := session.SimpleGet(ctx, rawURL(responseItem.HTMLURL))
			if err != nil {
				if resp != nil && resp.StatusCode != http.StatusNotFound {
					session.DiscardHTTPResponse(resp)
				}
				errChan <- err
				return
			}

			if resp.StatusCode == http.StatusOK {
				scanner := bufio.NewScanner(resp.Body)
				for scanner.Scan() {
					select {
					case <-ctx.Done():
						session.DiscardHTTPResponse(resp)
						return
					default:
					}
					line := scanner.Text()
					if line == "" {
						continue
					}
					for _, subdomain := range domainRegexp.FindAllString(normalizeContent(line), -1) {
						select {
						case <-ctx.Done():
							session.DiscardHTTPResponse(resp)
							return
						case results <- subscraping.Result{Source: name, Type: subscraping.Subdomain, Value: subdomain}:
							s.results++
						}
					}
				}
				session.DiscardHTTPResponse(resp)
			}

			for _, textMatch := range responseItem.TextMatches {
				select {
				case <-ctx.Done():
					return
				default:
				}
				for _, subdomain := range domainRegexp.FindAllString(normalizeContent(textMatch.Fragment), -1) {
					select {
					case <-ctx.Done():
						return
					case results <- subscraping.Result{Source: name, Type: subscraping.Subdomain, Value: subdomain}:
						s.results++
					}
				}
			}
		}(responseItem)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// Normalize content before matching, query unescape, remove tabs and new line chars
func normalizeContent(content string) string {
	normalizedContent, _ := url.QueryUnescape(content)
	normalizedContent = strings.ReplaceAll(normalizedContent, "\\t", "")
	normalizedContent = strings.ReplaceAll(normalizedContent, "\\n", "")
	return normalizedContent
}

// Raw URL to get the files code and match for subdomains
func rawURL(htmlURL string) string {
	domain := strings.ReplaceAll(htmlURL, "https://github.com/", "https://raw.githubusercontent.com/")
	return strings.ReplaceAll(domain, "/blob/", "/")
}

// DomainRegexp regular expression to match subdomains in github files code
func domainRegexp(domain string) *regexp.Regexp {
	rdomain := strings.ReplaceAll(domain, ".", "\\.")
	return regexp.MustCompile("(\\w[a-zA-Z0-9][a-zA-Z0-9-\\.]*)" + rdomain)
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "github"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
