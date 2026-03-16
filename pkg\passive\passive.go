package passive

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer for parallelization.
type Agent struct {
	sources          map[string]subscraping.Source
	RateLimiter      *ratelimit.Limiter
	MultiRateLimiter *ratelimit.MultiLimiter
}

// New creates a new passive results enum agent.
func New(sourceNames, excludedSourceNames []string, all bool) *Agent {
	agent := &Agent{}
	agent.sources = make(map[string]subscraping.Source)

	// Build the source list
	sources := make(map[string]subscraping.Source)
	if all {
		sources = AllSources
	} else if len(sourceNames) > 0 {
		for _, source := range sourceNames {
			if src, ok := AllSources[strings.ToLower(source)]; ok {
				sources[strings.ToLower(source)] = src
			}
		}
	} else {
		for _, source := range DefaultSources {
			if src, ok := AllSources[strings.ToLower(source)]; ok {
				sources[strings.ToLower(source)] = src
			}
		}
	}

	// Remove excluded sources
	for _, excludedSource := range excludedSourceNames {
		delete(sources, strings.ToLower(excludedSource))
	}

	agent.sources = sources
	return agent
}

// EnumerateSubdomains wraps EnumerateSubdomainsWithCtx with a background context
func (a *Agent) EnumerateSubdomains(domain string, keys *subscraping.Keys, timeout int, timeCh <-chan time.Time, yield func(string) bool) {
	a.EnumerateSubdomainsWithCtx(context.Background(), domain, keys, timeout, timeCh, yield)
}

// EnumerateSubdomainsWithCtx enumerates all subdomains for a given domain
func (a *Agent) EnumerateSubdomainsWithCtx(ctx context.Context, domain string, keys *subscraping.Keys, timeout int, timeCh <-chan time.Time, yield func(string) bool) {
	// ...
}
