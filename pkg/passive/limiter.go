package passive

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// RateLimiter shares provider budgets across a domain batch. Built-in requests
// use cancellable fixed windows. Custom adapters retain one shared legacy limiter
// because they may access Session.MultiRateLimiter directly.
// Call Close after all enumerations finish.
type RateLimiter struct {
	sources       map[string]*sourceBudget
	legacy        *ratelimit.MultiLimiter
	legacySources map[string]bool
	stop          func() bool
}

type sourceBudget struct {
	mu               sync.Mutex
	limit, remaining uint
	period           time.Duration
	start            time.Time
}

// NewRateLimiter creates provider budgets shared by a domain batch.
// Per-source settings override the global default, as for single-domain runs.
func (a *Agent) NewRateLimiter(ctx context.Context, globalRateLimit int, custom *subscraping.CustomRateLimit) (*RateLimiter, error) {
	if custom == nil {
		custom = &subscraping.CustomRateLimit{}
	}

	limiter := &RateLimiter{sources: make(map[string]*sourceBudget, len(a.sources)), legacySources: make(map[string]bool)}
	now := time.Now()

	for _, source := range a.sources {
		limit, period := resolveSourceRateLimit(globalRateLimit, custom, source.Name())
		if _, legacy := source.(*serializedSource); legacy {
			legacyLimit, legacyPeriod := limit, period
			if legacyLimit == 0 {
				legacyLimit, legacyPeriod = math.MaxUint32, time.Millisecond
			}

			var err error

			limiter.legacy, err = addRateLimiter(ctx, limiter.legacy, source.Name(), legacyLimit, legacyPeriod)
			if err != nil {
				_ = limiter.Close()

				return nil, err
			}

			limiter.legacySources[source.Name()] = true
		}

		var budget *sourceBudget

		if limit > 0 {
			budget = &sourceBudget{limit: limit, remaining: limit, period: period, start: now}
		}

		limiter.sources[source.Name()] = budget
	}

	if limiter.legacy != nil {
		limiter.stop = context.AfterFunc(ctx, func() { limiter.legacy.Stop() })
	}

	return limiter, nil
}

// Close releases the legacy custom-source limiter, if any.
func (l *RateLimiter) Close() error {
	if l.stop != nil {
		l.stop()
	}

	if l.legacy != nil {
		l.legacy.Stop()
	}

	return nil
}

// Wait waits for a source budget. Legacy custom adapters keep their original
// blocking Take behavior; their runs are serialized by the custom-source gate.
func (l *RateLimiter) Wait(ctx context.Context, source string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if l.legacySources[source] {
		if err := l.legacy.Take(source); err != nil {
			return err
		}
		return ctx.Err()
	}

	budget, ok := l.sources[source]
	if !ok {
		return fmt.Errorf("no rate limit configured for source %s", source)
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if budget == nil {
			return nil
		}

		budget.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(budget.start)

		if elapsed >= budget.period {
			// Keep window boundaries anchored to batch creation even after idle time.
			budget.start = now.Add(-(elapsed % budget.period))
			budget.remaining = budget.limit
			elapsed = now.Sub(budget.start)
		}

		if budget.remaining > 0 {
			budget.remaining--
			budget.mu.Unlock()

			return nil
		}

		delay := budget.period - elapsed
		budget.mu.Unlock()
		timer := time.NewTimer(delay)

		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
