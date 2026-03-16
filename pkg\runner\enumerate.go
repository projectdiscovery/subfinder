package runner

import (
	"bytes"
	"context"
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

// EnumerateSingleDomain performs subdomain enumeration against a single domain
func (r *Runner) EnumerateSingleDomain(ctx context.Context, domain string, outputs []io.Writer) error {
	gologger.Info().Msgf("Enumerating subdomains for %s\n", domain)

	// Get the rate limiters from options
	var rateLimiter *ratelimit.Limiter
	var multiRateLimiter *ratelimit.MultiLimiter

	if r.options.RateLimitMinute > 0 {
		rateLimiter = ratelimit.New(context.Background(), uint(r.options.RateLimitMinute), time.Minute)
	} else if r.options.RateLimit > 0 {
		rateLimiter = ratelimit.New(context.Background(), uint(r.options.RateLimit), time.Second)
	}

	// Build per-source rate limiters
	if len(r.options.SourceRateLimits) > 0 {
		rl := make(map[string]*ratelimit.Options)
		for _, item := range r.options.SourceRateLimits {
			// format: source=N/s or source=N/m
			parts := strings.SplitN(item, "=", 2)
			if len(parts) != 2 {
				continue
			}
			source := parts[0]
			limitStr := parts[1]
			// parse N/s or N/m
			var count uint
			var unit time.Duration
			if strings.HasSuffix(limitStr, "/m") || strings.HasSuffix(limitStr, "m") {
				var n int
				if _, err := fmt.Sscanf(strings.TrimSuffix(strings.TrimSuffix(limitStr, "/m"), "m"), "%d", &n); err == nil {
					count = uint(n)
					unit = time.Minute
				}
			} else if strings.HasSuffix(limitStr, "/s") || strings.HasSuffix(limitStr, "s") {
				var n int
				if _, err := fmt.Sscanf(strings.TrimSuffix(strings.TrimSuffix(limitStr, "/s"), "s"), "%d", &n); err == nil {
					count = uint(n)
					unit = time.Second
				}
			} else {
				var n int
				if _, err := fmt.Sscanf(limitStr, "%d", &n); err == nil {
					count = uint(n)
					unit = time.Second
				}
			}
			if count > 0 {
				rl[source] = &ratelimit.Options{Key: source, IsUnlimited: false, MaxCount: count, Duration: unit}
			}
		}
		if len(rl) > 0 {
			opts := make([]*ratelimit.Options, 0, len(rl))
			for _, v := range rl {
				opts = append(opts, v)
			}
			var err error
			multiRateLimiter, err = ratelimit.NewMultiLimiter(context.Background(), opts...)
			if err != nil {
				gologger.Warning().Msgf("Could not create multi rate limiter: %s\n", err)
			}
		}
	}
