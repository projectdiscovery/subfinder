// Package chaos logic
package chaos

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// baseURL is the Chaos API endpoint. It is a variable so tests can point the
// source at a local server.
var baseURL = "https://dns.projectdiscovery.io/dns"

// Source is the passive scraping agent
type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.mu.Lock()
	apiKeys := s.apiKeys
	s.mu.Unlock()

	go func() {
		var stats subscraping.Statistics
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		keys := subscraping.NewKeyRing(apiKeys)
		if keys.Empty() {
			stats.Skipped = true
			return
		}

		// The request goes through the session like every other source, so it
		// honors -proxy, -timeout, the rate limits and -max-response-body-size.
		resp, err := keys.Do(session, func(key string) (*http.Response, error) {
			stats.Requests++
			return session.Get(ctx, fmt.Sprintf("%s/%s/subdomains", baseURL, domain), "", map[string]string{
				"Authorization": key,
				"Accept":        "application/json",
			})
		})
		// Registered before the error check: a non-200 reply comes back as a
		// response and an error together. DiscardHTTPResponse ignores nil.
		defer session.DiscardHTTPResponse(resp)
		if err != nil {
			s.sendError(ctx, results, err)
			stats.Errors++
			return
		}

		// The body is {"domain": "...", "subdomains": ["a", "b", ...], ...}.
		// Stream the list instead of decoding it whole: large domains can
		// return a very long one.
		decoder := json.NewDecoder(resp.Body)
		if err := seekSubdomains(decoder); err != nil {
			s.sendError(ctx, results, err)
			stats.Errors++
			return
		}
		for decoder.More() {
			var subdomain string
			if err := decoder.Decode(&subdomain); err != nil {
				s.sendError(ctx, results, err)
				stats.Errors++
				return
			}
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: fmt.Sprintf("%s.%s", subdomain, domain)}:
				stats.Results++
			}
		}
		// More also reports false on a read error, so a truncated body only
		// shows up when the closing tokens are checked.
		if err := finishResponse(decoder); err != nil {
			s.sendError(ctx, results, err)
			stats.Errors++
		}
	}()

	return results
}

// sendError reports err unless the consumer has stopped reading and the
// context is done, so the goroutine can exit and close results.
func (s *Source) sendError(ctx context.Context, results chan<- subscraping.Result, err error) {
	select {
	case <-ctx.Done():
	case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}:
	}
}

// seekSubdomains advances the decoder to the first element of the
// "subdomains" array, skipping any other keys of the top-level object.
func seekSubdomains(decoder *json.Decoder) error {
	if err := expectDelim(decoder, '{'); err != nil {
		return err
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if key, ok := token.(string); ok && key == "subdomains" {
			return expectDelim(decoder, '[')
		}
		var skip json.RawMessage
		if err := decoder.Decode(&skip); err != nil {
			return err
		}
	}
	return fmt.Errorf("no subdomains field in response")
}

// finishResponse consumes the end of the "subdomains" array and the rest of
// the top-level object.
func finishResponse(decoder *json.Decoder) error {
	if err := expectDelim(decoder, ']'); err != nil {
		return err
	}
	for decoder.More() {
		if _, err := decoder.Token(); err != nil {
			return err
		}
		var skip json.RawMessage
		if err := decoder.Decode(&skip); err != nil {
			return err
		}
	}
	return expectDelim(decoder, '}')
}

func expectDelim(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != want {
		return fmt.Errorf("unexpected token %v in response, expected %v", token, want)
	}
	return nil
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "chaos"
}

func (s *Source) IsDefault() bool {
	return true
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
