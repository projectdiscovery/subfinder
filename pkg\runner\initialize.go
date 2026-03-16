package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// parseRateLimitValue parses rate limit string formats:
// "N", "N/s", "N/m" into count and duration
func parseRateLimitValue(s string) (uint, time.Duration, error) {
	s = strings.TrimSpace(s)

	if strings.HasSuffix(s, "/m") {
		trimmed := strings.TrimSuffix(s, "/m")
		var n uint
		if _, err := fmt.Sscanf(trimmed, "%d", &n); err != nil {
			return 0, 0, fmt.Errorf("invalid rate limit: %s", s)
		}
		return n, time.Minute, nil
	}

	if strings.HasSuffix(s, "/s") {
		trimmed := strings.TrimSuffix(s, "/s")
		var n uint
		if _, err := fmt.Sscanf(trimmed, "%d", &n); err != nil {
			return 0, 0, fmt.Errorf("invalid rate limit: %s", s)
		}
		return n, time.Second, nil
	}

	var n uint
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, 0, fmt.Errorf("invalid rate limit: %s", s)
	}
	return n, time.Second, nil
}

// initializeRateLimiters creates rate limiters from options
func (r *Runner) initializeRateLimiters(ctx context.Context) error {
	// Global rate limiter
	if r.options.RateLimitMinute > 0 {
		r.rateLimiter = ratelimit.New(ctx, uint(r.options.RateLimitMinute), time.Minute)
	} else if r.options.RateLimit > 0 {
		r.rateLimiter = ratelimit.New(ctx, uint(r.options.RateLimit), time.Second)
	}

	// Per-source rate limiters
	if len(r.options.SourceRateLimits) > 0 {
		rlOpts := make([]*ratelimit.Options, 0, len(r.options.SourceRateLimits))
		for _, item := range r.options.SourceRateLimits {
			parts := strings.SplitN(item, "=", 2)
			if len(parts) != 2 {
				gologger.Warning().Msgf("Invalid source rate limit format: %s (expected source=N/duration)\n", item)
				continue
			}
			source := strings.ToLower(strings.TrimSpace(parts[0]))
			count, duration, err := parseRateLimitValue(parts[1])
			if err != nil {
				gologger.Warning().Msgf("Could not parse rate limit for source %s: %s\n", source, err)
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
			r.multiRateLimiter, err = ratelimit.NewMultiLimiter(ctx, rlOpts...)
			if err != nil {
				return fmt.Errorf("could not create multi rate limiter: %s", err)
			}
		}
	}

	return nil
}
