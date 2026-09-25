package gitlab

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/tomnomnom/linkheader"
)

// Source is the passive scraping agent
type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

// runState holds counters shared only by workers of one run.
type runState struct {
	errors   atomic.Int32
	results  atomic.Int32
	requests atomic.Int32
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
	s.mu.Lock()
	apiKeys := s.apiKeys
	s.mu.Unlock()

	go func() {
		var stats subscraping.Statistics
		var run runState
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			stats.Errors = int(run.errors.Load())
			stats.Results = int(run.results.Load())
			stats.Requests = int(run.requests.Load())
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(apiKeys, s.Name())
		if randomApiKey == "" {
			return
		}

		headers := map[string]string{"PRIVATE-TOKEN": randomApiKey}

		searchURL := fmt.Sprintf("https://gitlab.com/api/v4/search?scope=blobs&search=%s&per_page=100", domain)
		s.enumerate(ctx, searchURL, domainRegexp(domain), headers, session, results, &run)

	}()

	return results
}

func (s *Source) enumerate(ctx context.Context, searchURL string, domainRegexp *regexp.Regexp, headers map[string]string, session *subscraping.Session, results chan subscraping.Result, run *runState) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	run.requests.Add(1)
	resp, err := session.Get(ctx, searchURL, "", headers)
	if err != nil && resp == nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		run.errors.Add(1)
		session.DiscardHTTPResponse(resp)
		return
	}

	defer session.DiscardHTTPResponse(resp)

	var items []item
	err = jsoniter.NewDecoder(resp.Body).Decode(&items)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		run.errors.Add(1)
		return
	}

	var wg sync.WaitGroup
	wg.Add(len(items))

	for _, it := range items {
		go func(item item) {
			defer wg.Done()
			// The original item.Path causes 404 error because the Gitlab API is expecting the url encoded path
			fileUrl := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s/raw?ref=%s", item.ProjectId, url.QueryEscape(item.Path), item.Ref)
			run.requests.Add(1)
			resp, err := session.Get(ctx, fileUrl, "", headers)
			if err != nil {
				if resp == nil || (resp != nil && resp.StatusCode != http.StatusNotFound) {
					session.DiscardHTTPResponse(resp)

					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					run.errors.Add(1)
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
						run.results.Add(1)
					}
				}
				session.DiscardHTTPResponse(resp)
			}
		}(it)
	}

	linksHeader := linkheader.Parse(resp.Header.Get("Link"))
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
				run.errors.Add(1)
				return
			}

			s.enumerate(ctx, nextURL, domainRegexp, headers, session, results, run)
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

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys = slices.Clone(keys)
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
