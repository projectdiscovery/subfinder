package passive

import (
	"context"
	"time"

	"github.com/projectdiscovery/ratelimit"
)

// addRateLimiter ensures a MultiLimiter exists and adds a per-source limiter.
// - If ml is nil, a new MultiLimiter is created.
// - Negative max values are clamped to 0 and interpreted as "no limiter" (no throttling).
// - A max == 0 means unlimited, so we don't add a limiter for that source.
// - The provided duration is preserved when creating the limiter.
func addRateLimiter(ctx context.Context, ml *ratelimit.MultiLimiter, source string, max int, dur time.Duration) (*ratelimit.MultiLimiter, error) {
	// Ensure we have a multi limiter to work with
	if ml == nil {
		ml = ratelimit.NewMultiLimiter()
	}

	// Clamp negative rates to 0 (treat as unlimited / no limiter)
	if max < 0 {
		max = 0
	}

	// If max is 0 we treat it as unlimited and do not add a limiter for the source
	if max == 0 {
		return ml, nil
	}

	// Preserve duration as given when creating the limiter
	l := ratelimit.NewLimiter(max, dur)

	// Add or replace the limiter for the source in the multi-limiter
	ml.Add(source, l)

	return ml, nil
}
