package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// initializeRateLimiters creates rate limiters based on provided options
func (r *Runner) initializeRateLimiters(ctx context.Context) error {
	// Global rate limiter
	if r.options.RateLimitMinute > 0 {
		r.rateLimiter = ratelimit.New(ctx, uint(r.options.RateLimitMinute), time.Minute)
	} else if r.options.RateLimit > 0 {
		r.rateLimiter = ratelimit.New(ctx, uint(r.options.RateLimit), time.Second)
	}

	// Per-source rate limiters (-rls source=N/duration)
	if len(r.options.SourceRateLimits) > 0 {
		rlOpts := make([]*ratelimit.Options, 0, len(r.options.SourceRateLimits))
		for _, item := range r.options.SourceRateLimits {
			source, count, duration, parseErr := parseSourceRateLimitOption(item)
			if parseErr != nil {
				gologger.Warning().Msgf("Could not parse source rate limit '%s': %s\n", item, parseErr)
				continue
			}
			gologger.Debug().Msgf("Setting rate limit for source %s: %d per %s\n", source, count, duration)
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
				return fmt.Errorf("could not create multi rate limiter: %w", err)
			}
		}
	}

	return nil
}

// parseSourceRateLimitOption parses "source=N/duration" format
func parseSourceRateLimitOption(item string) (source string, count uint, duration time.Duration, err error) {
	parts := strings.SplitN(item, "=", 2)
	if len(parts) != 2 {
		err = fmt.Errorf("expected format source=N/duration, got: %s", item)
		return
	}
	source = strings.ToLower(strings.TrimSpace(parts[0]))
	count, duration, err = parseRateLimitValue(strings.TrimSpace(parts[1]))
	return
}

// parseRateLimitValue parses "N", "N/s", "N/m" into count and duration
func parseRateLimitValue(s string) (uint, time.Duration, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasSuffix(s, "/m"):
		n, err := parseUintStr(strings.TrimSuffix(s, "/m"))
		return n, time.Minute, err
	case strings.HasSuffix(s, "/s"):
		n, err := parseUintStr(strings.TrimSuffix(s, "/s"))
		return n, time.Second, err
	default:
		n, err := parseUintStr(s)
		return n, time.Second, err
	}
}

func parseUintStr(s string) (uint, error) {
	var n uint
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", s)
	}
	return n, nil
}
