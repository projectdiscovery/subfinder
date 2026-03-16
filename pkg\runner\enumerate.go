package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/hako/durafmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// EnumerateSingleDomain performs subdomain enumeration
func (r *Runner) EnumerateSingleDomain(ctx context.Context, domain string, outputs []io.Writer) error {
	gologger.Info().Msgf("Enumerating subdomains for %s\n", domain)

	// Create rate limiters
	var rateLimiter *ratelimit.Limiter
	var multiRateLimiter *ratelimit.MultiLimiter

	if r.options.RateLimitMinute > 0 {
		rateLimiter = ratelimit.New(context.Background(), uint(r.options.RateLimitMinute), time.Minute)
	} else if r.options.RateLimit > 0 {
		rateLimiter = ratelimit.New(context.Background(), uint(r.options.RateLimit), time.Second)
	}

	if len(r.options.SourceRateLimits) > 0 {
		rlOpts := []*ratelimit.Options{}
		for _, item := range r.options.SourceRateLimits {
			parts := strings.SplitN(item, "=", 2)
			if len(parts) != 2 {
				continue
			}
			source := strings.ToLower(strings.TrimSpace(parts[0]))
			limitStr := strings.TrimSpace(parts[1])
			count, dur, err := parseRateLimitStr(limitStr)
			if err != nil {
				gologger.Warning().Msgf("Could not parse rate limit for %s: %s\n", item, err)
				continue
			}
			rlOpts = append(rlOpts, &ratelimit.Options{
				Key:         source,
				IsUnlimited: false,
				MaxCount:    count,
				Duration:    dur,
			})
		}
		if len(rlOpts) > 0 {
			var err error
			multiRateLimiter, err = ratelimit.NewMultiLimiter(context.Background(), rlOpts...)
			if err != nil {
				gologger.Warning().Msgf("Could not create per-source rate limiter: %s\n", err)
			}
		}
	}
	
	// Use rate limiters in passive enumeration
	// ...
}

func parseRateLimitStr(s string) (uint, time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "/m") {
		n, err := parseUintVal(strings.TrimSuffix(s, "/m"))
		return n, time.Minute, err
	}
	if strings.HasSuffix(s, "/s") {
		n, err := parseUintVal(strings.TrimSuffix(s, "/s"))
		return n, time.Second, err
	}
	n, err := parseUintVal(s)
	return n, time.Second, err
}

func parseUintVal(s string) (uint, error) {
	var n uint
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", s)
	}
	return n, nil
}
