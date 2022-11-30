package gitlab

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/tomnomnom/linkheader"
)

// Source is the passive scraping agent
type Source struct {
	apiKeys []string
}

type item struct {
	Data      string `json:"data"`
	ProjectId int    `json:"project_id"`
	Path      string `json:"path"`
	Ref       string `json:"ref"`
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			return
		}

		headers := map[string]string{"PRIVATE-TOKEN": randomApiKey}

		searchURL := fmt.Sprintf("https://gitlab.com/api/v4/search?scope=blobs&search=%s&per_page=100", domain)
		s.enumerate(ctx, searchURL, domainRegexp(domain), headers, session, results)

	}()

	return results
}

func (s *Source) enumerate(ctx context.Context, searchURL string, domainRegexp *regexp.Regexp, headers map[string]string, session *subscraping.Session, results chan subscraping.Result) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := session.Get(ctx, searchURL, "", headers)
	if err != nil && resp == nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		session.DiscardHTTPResponse(resp)
		return
	}

	defer resp.Body.Close()

	var items []item
	err = jsoniter.NewDecoder(resp.Body).Decode(&items)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		return
	}

	var wg sync.WaitGroup
	wg.Add(len(items))

	for _, it := range items {
		go func(item item) {
			// The original item.Path causes 404 error because the Gitlab API is expecting the url encoded path
			fileUrl := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s/raw?ref=%s", item.ProjectId, url.QueryEscape(item.Path), item.Ref)
			resp, err := session.Get(ctx, fileUrl, "", headers)
			if err != nil {
				if resp == nil || (resp != nil && resp.StatusCode != http.StatusNotFound) {
					session.DiscardHTTPResponse(resp)

					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					return
				}
			}

			if resp.StatusCode == http.StatusOK {
				scanner := bufio.NewScanner(resp.Body)
				for scanner.Scan() {
					line := scanner.Text()
					if line == "" {
						continue
					}
					for _, subdomain := range domainRegexp.FindAllString(line, -1) {
						results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
					}
				}
				resp.Body.Close()
			}
			defer wg.Done()
		}(it)
	}

	// Links header, first, next, last...
	linksHeader := linkheader.Parse(resp.Header.Get("Link"))
	// Process the next link recursively
	for _, link := range linksHeader {
		if link.Rel == "next" {
			nextURL, err := url.QueryUnescape(link.URL)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				return
			}

			// TODO: hardcoded for testing, should be a source internal rate limit #718
			time.Sleep(2 * time.Second)

			s.enumerate(ctx, nextURL, domainRegexp, headers, session, results)
		}
	}

	wg.Wait()
}

func domainRegexp(domain string) *regexp.Regexp {
	rdomain := strings.ReplaceAll(domain, ".", "\\.")
	return regexp.MustCompile("(\\w[a-zA-Z0-9][a-zA-Z0-9-\\.]*)" + rdomain)
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "gitlab"
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
