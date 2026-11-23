package runner

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// keyProbeDomain is enumerated when no -d is given. It only needs to be a
// domain every source accepts; the key status comes from the responses.
const keyProbeDomain = "projectdiscovery.io"

// KeyStatus is the outcome of probing one provider key.
type KeyStatus string

const (
	KeyValid       KeyStatus = "valid"
	KeyInvalid     KeyStatus = "invalid"
	KeyRateLimited KeyStatus = "rate-limited"
	KeyError       KeyStatus = "error"
	// KeySkipped means the source did not use the key, usually a malformed one.
	KeySkipped KeyStatus = "skipped"
)

// KeyCheck is the result of probing one configured key of a source.
type KeyCheck struct {
	Source string    `json:"source"`
	Key    int       `json:"key"`
	Status KeyStatus `json:"status"`
	Error  string    `json:"error,omitempty"`
}

// CheckKeys probes every configured key of the selected sources, one key per
// request so a bad key cannot hide behind a good one, and writes a status per key.
func (r *Runner) CheckKeys(ctx context.Context, writer io.Writer) error {
	checks := r.checkKeys(ctx)
	if r.options.JSON {
		encoder := json.NewEncoder(writer)
		for _, check := range checks {
			if err := encoder.Encode(check); err != nil {
				return err
			}
		}
		return nil
	}
	if len(checks) == 0 {
		_, err := fmt.Fprintln(writer, "no provider keys configured")
		return err
	}
	for _, check := range checks {
		line := fmt.Sprintf("%s key %d: %s", check.Source, check.Key, check.Status)
		if check.Error != "" {
			line += " (" + check.Error + ")"
		}
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) checkKeys(ctx context.Context) []KeyCheck {
	domain := keyProbeDomain
	if len(r.options.Domain) > 0 {
		domain = r.options.Domain[0]
	}

	var (
		mu     sync.Mutex
		checks []KeyCheck
		wg     sync.WaitGroup
	)
	for _, name := range r.keyedSources() {
		wg.Add(1)
		// Keys of one source run in sequence to respect its rate limit.
		go func(name string, keys []string) {
			defer wg.Done()
			for i, key := range keys {
				check := r.probeKey(ctx, name, key, domain)
				check.Key = i + 1
				mu.Lock()
				checks = append(checks, check)
				mu.Unlock()
			}
		}(name, r.providerKeys[name])
	}
	wg.Wait()

	slices.SortFunc(checks, func(a, b KeyCheck) int {
		return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.Key, b.Key))
	})
	return checks
}

// keyedSources returns the names of the sources with configured keys, narrowed
// by -s and -es. Custom sources registered in NameSourceMap are included.
func (r *Runner) keyedSources() []string {
	var names []string
	for name, source := range passive.NameSourceMap {
		if source.KeyRequirement() == subscraping.NoKey || len(r.providerKeys[name]) == 0 {
			continue
		}
		if len(r.options.Sources) > 0 && !slices.Contains(r.options.Sources, name) {
			continue
		}
		if slices.Contains(r.options.ExcludeSources, name) {
			continue
		}
		names = append(names, name)
	}
	return names
}

func (r *Runner) probeKey(ctx context.Context, name, key, domain string) KeyCheck {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	agent := passive.NewWithProviderConfig([]string{name}, nil, false, false, map[string][]string{name: {key}})
	results := agent.EnumerateSubdomainsWithCtx(ctx, domain, r.options.Proxy, r.options.RateLimit, r.options.Timeout,
		time.Duration(r.options.Timeout)*time.Second,
		passive.WithCustomRateLimit(r.rateLimit),
		passive.WithMaxResults(1),
		passive.WithMaxResponseBodySize(int64(r.options.MaxResponseBodySize)),
	)

	check := KeyCheck{Source: name, Status: KeyValid}
	var firstErr error
	for result := range results {
		switch result.Type {
		case subscraping.Subdomain:
			// One result proves the key works; stop spending its quota.
			firstErr = nil
			cancel()
		case subscraping.Error:
			if firstErr == nil && ctx.Err() == nil {
				firstErr = result.Error
			}
		}
	}
	switch {
	case firstErr != nil:
		check.Status, check.Error = classifyKeyError(firstErr, key)
	case agent.GetStatistics()[name].Skipped:
		check.Status = KeySkipped
	}
	return check
}

func classifyKeyError(err error, key string) (KeyStatus, string) {
	var statusErr *subscraping.StatusCodeError
	if errors.As(err, &statusErr) {
		message := fmt.Sprintf("status %d", statusErr.StatusCode)
		switch statusErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return KeyInvalid, message
		case http.StatusTooManyRequests:
			return KeyRateLimited, message
		}
		return KeyError, message
	}
	return KeyError, redactKey(err.Error(), key)
}

// redactKey removes the key from an error message, since sources often put it
// in the request URL. Multi-part keys ("user:secret") are redacted per part.
func redactKey(message, key string) string {
	for _, part := range append([]string{key}, strings.Split(key, ":")...) {
		if part != "" {
			message = strings.ReplaceAll(message, part, "[redacted]")
		}
	}
	return message
}
