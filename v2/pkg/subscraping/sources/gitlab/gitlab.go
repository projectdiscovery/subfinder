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

	// "wiki_blobs", "commits", "blobs", "notes" are moved to GitLab Premium in 13.9. ref: https://docs.gitlab.com/ee/api/search.html#scope-wiki_blobs
	scopes := []string{"projects", "issues", "merge_requests", "milestones", "snippet_titles", "users"}
	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			return
		}
		headers := map[string]string{"PRIVATE-TOKEN": randomApiKey}
		for _, scope := range scopes {
			searchURL := fmt.Sprintf("https://gitlab.com/api/v4/search?scope=%s&search=%s&order_by=created_at&sort=desc&per_page=1000", scope, domain)
			s.enumerate(ctx, searchURL, scope, domainRegexp(domain), headers, session, results)
		}
	}()

	return results
}

func (s *Source) enumerate(ctx context.Context, searchURL string, scope string, domainRegexp *regexp.Regexp, headers map[string]string, session *subscraping.Session, results chan subscraping.Result) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := session.Get(ctx, searchURL, "", headers)
	if err != nil && resp == nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		s.errors++
		session.DiscardHTTPResponse(resp)
		return
	}

	defer resp.Body.Close()

	var items []map[string]interface{}
	err = jsoniter.NewDecoder(resp.Body).Decode(&items)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		return
	}

	var wg sync.WaitGroup
	wg.Add(len(items))

	for _, it := range items {
		go func(item map[string]interface{}) {
			defer wg.Done()
			// The original item.Path causes 404 error because the Gitlab API is expecting the url encoded path
			fileUrl := buildUrl(scope, item)
			resp, err := session.Get(ctx, fileUrl, "", headers)
			if err != nil {
				if resp == nil || (resp != nil && resp.StatusCode != http.StatusNotFound) {
					session.DiscardHTTPResponse(resp)
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
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
						s.results++
					}
				}
				resp.Body.Close()
			}
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
				s.errors++
				return
			}

			s.enumerate(ctx, nextURL, scope, domainRegexp, headers, session, results)
		}
	}

	wg.Wait()
}

func buildUrl(scope string, item map[string]interface{}) string {
	if webURL, exists := item["web_url"].(string); exists {
		switch scope {
		case "projects", "issues", "merge_requests", "milestones", "snippet_titles", "users", "commits", "wiki_blobs":
			return webURL
		}
	}

	if scope == "blobs" {
		if path, ok := item["path"].(string); ok {
			encodedPath := strings.Replace(path, "/", "%2f", -1)
			if projectID, ok := item["project_id"].(int); ok {
				if ref, ok := item["ref"].(string); ok {
					return fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s/raw?ref=%s", projectID, encodedPath, ref)
				}
			}
		}
	}
	return ""
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

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
