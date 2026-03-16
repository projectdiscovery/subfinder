package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/hako/durafmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// parseSourceRateLimit parses a source rate limit string in "source=N/duration" format
// and returns the source name, count, and duration.
// Supported duration formats: /s, /m (or s, m suffix)
func parseSourceRateLimit(s string) (source string, count uint, duration time.Duration, err error) {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		err = fmt.Errorf("invalid source rate limit format: %s (expected source=N/duration)", s)
		return
	}
	source = strings.ToLower(strings.TrimSpace(parts[0]))
	limitStr := strings.TrimSpace(parts[1])

	count, duration, err = parseRateLimit(limitStr)
	return
}

// parseRateLimit parses a rate limit string like "N/s", "N/m", "Ns", "Nm" or just "N"
func parseRateLimit(s string) (count uint, duration time.Duration, err error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "/m") {
		s = strings.TrimSuffix(s, "/m")
		n, e := parseUint(s)
		if e != nil {
			err = fmt.Errorf("invalid rate limit: %s", s)
			return
		}
		count = n
		duration = time.Minute
		return
	}
	if strings.HasSuffix(s, "/s") {
		s = strings.TrimSuffix(s, "/s")
		n, e := parseUint(s)
		if e != nil {
			err = fmt.Errorf("invalid rate limit: %s", s)
			return
		}
		count = n
		duration = time.Second
		return
	}
	if strings.HasSuffix(s, "m") {
		s = strings.TrimSuffix(s, "m")
		n, e := parseUint(s)
		if e != nil {
			err = fmt.Errorf("invalid rate limit: %s", s)
			return
		}
		count = n
		duration = time.Minute
		return
	}
	if strings.HasSuffix(s, "s") {
		s = strings.TrimSuffix(s, "s")
		n, e := parseUint(s)
		if e != nil {
			err = fmt.Errorf("invalid rate limit: %s", s)
			return
		}
		count = n
		duration = time.Second
		return
	}
	n, e := parseUint(s)
	if e != nil {
		err = fmt.Errorf("invalid rate limit: %s", s)
		return
	}
	count = n
	duration = time.Second
	return
}

func parseUint(s string) (uint, error) {
	var n uint
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// EnumerateSingleDomain performs subdomain enumeration against a single domain
func (r *Runner) EnumerateSingleDomain(ctx context.Context, domain string, outputs []io.Writer) error {
	gologger.Info().Msgf("Enumerating subdomains for %s\n", domain)

	// Setup rate limiters
	var rateLimiter *ratelimit.Limiter
	var multiRateLimiter *ratelimit.MultiLimiter

	// Global rate limiter
	if r.options.RateLimitMinute > 0 {
		rateLimiter = ratelimit.New(context.Background(), uint(r.options.RateLimitMinute), time.Minute)
	} else if r.options.RateLimit > 0 {
		rateLimiter = ratelimit.New(context.Background(), uint(r.options.RateLimit), time.Second)
	}

	// Per-source rate limiters
	if len(r.options.SourceRateLimits) > 0 {
		rlOpts := make([]*ratelimit.Options, 0)
		for _, item := range r.options.SourceRateLimits {
			source, count, duration, err := parseSourceRateLimit(item)
			if err != nil {
				gologger.Warning().Msgf("Could not parse source rate limit %s: %s\n", item, err)
				continue
			}
			rlOpts = append(rlOpts, &ratelimit.Options{
				Key:         source,
				IsUnlimited: false,
				MaxCount:    count,
				Duration:    duration,
			})
		}
		if len(rlOpts) > 0 {
			var err error
			multiRateLimiter, err = ratelimit.NewMultiLimiter(context.Background(), rlOpts...)
			if err != nil {
				gologger.Warning().Msgf("Could not create multi rate limiter: %s\n", err)
			}
		}
	}

	now := time.Now()
	var wg sync.WaitGroup
	var writeMutex sync.Mutex
	subdomainFound := make(chan subscraping.Result)

	// Run all the sources
	for _, source := range r.passiveAgent.GetSources() {
		wg.Add(1)
		go func(source subscraping.Source) {
			defer wg.Done()
			// Run the source with rate limiters
			// ...
		}(source)
	}
