package passive

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type EnumerationOptions struct {
	customRateLimiter *subscraping.CustomRateLimit
}

type EnumerateOption func(opts *EnumerationOptions)

func WithCustomRateLimit(crl *subscraping.CustomRateLimit) EnumerateOption {
	return func(opts *EnumerationOptions) {
		opts.customRateLimiter = crl
	}
}

// EnumerateSubdomains wraps EnumerateSubdomainsWithCtx with an empty context
func (a *Agent) EnumerateSubdomains(domain string, proxy string, rateLimit int, timeout int, maxEnumTime time.Duration, options ...EnumerateOption) chan subscraping.Result {
	return a.EnumerateSubdomainsWithCtx(context.Background(), domain, proxy, rateLimit, timeout, maxEnumTime, options...)
}

// EnumerateSubdomainsWithCtx enumerates all the subdomains for a given domain
func (a *Agent) EnumerateSubdomainsWithCtx(ctx context.Context, domain string, proxy string, rateLimit int, timeout int, maxEnumTime time.Duration, options ...EnumerateOption) chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		var enumerateOptions EnumerationOptions
		for _, enumerateOption := range options {
			enumerateOption(&enumerateOptions)
		}

		multiRateLimiter, err := a.buildMultiRateLimiter(ctx, rateLimit, enumerateOptions.customRateLimiter)
		if err != nil {
			results <- subscraping.Result{
				Type: subscraping.Error, Error: fmt.Errorf("could not init multi rate limiter for %s: %s", domain, err),
			}
			return
		}
		session, err := subscraping.NewSession(domain, proxy, multiRateLimiter, timeout)
		if err != nil {
			results <- subscraping.Result{
				Type: subscraping.Error, Error: fmt.Errorf("could not init passive session for %s: %s", domain, err),
			}
			return
		}
		defer session.Close()

		ctx, cancel := context.WithTimeout(ctx, maxEnumTime)

		wg := &sync.WaitGroup{}
		// Run each source in parallel on the target domain
		for _, runner := range a.sources {
			wg.Add(1)
			go func(source subscraping.Source) {
				defer wg.Done()
				ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, source.Name())
				for resp := range source.Run(ctxWithValue, domain, session) {
					select {
					case <-ctx.Done():
						return
					case results <- resp:
					}
				}
			}(runner)
		}
		wg.Wait()
		cancel()
	}()
	return results
}

func (a *Agent) buildMultiRateLimiter(ctx context.Context, globalRateLimit int, rateLimit *subscraping.CustomRateLimit) (*ratelimit.MultiLimiter, error) {
	var multiRateLimiter *ratelimit.MultiLimiter
	var err error
	for _, source := range a.sources {
		var rl uint
		if sourceRateLimit, ok := rateLimit.Custom.Get(strings.ToLower(source.Name())); ok {
			rl = sourceRateLimitOrDefault(uint(globalRateLimit), sourceRateLimit)
		}

		if rl > 0 {
			multiRateLimiter, err = addRateLimiter(ctx, multiRateLimiter, source.Name(), rl, time.Second)
		} else {
			multiRateLimiter, err = addRateLimiter(ctx, multiRateLimiter, source.Name(), math.MaxUint32, time.Millisecond)
		}

		if err != nil {
			break
		}
	}
	return multiRateLimiter, err
}

func sourceRateLimitOrDefault(defaultRateLimit uint, sourceRateLimit uint) uint {
	if sourceRateLimit > 0 {
		return sourceRateLimit
	}
	return defaultRateLimit
}

func addRateLimiter(ctx context.Context, multiRateLimiter *ratelimit.MultiLimiter, key string, maxCount uint, duration time.Duration) (*ratelimit.MultiLimiter, error) {
	if multiRateLimiter == nil {
		mrl, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
			Key:         key,
			IsUnlimited: maxCount == math.MaxUint32,
			MaxCount:    maxCount,
			Duration:    duration,
		})
		return mrl, err
	}
	err := multiRateLimiter.Add(&ratelimit.Options{
		Key:         key,
		IsUnlimited: maxCount == math.MaxUint32,
		MaxCount:    maxCount,
		Duration:    duration,
	})
	return multiRateLimiter, err
}

func (a *Agent) GetStatistics() map[string]subscraping.Statistics {
	stats := make(map[string]subscraping.Statistics)
	sort.Slice(a.sources, func(i, j int) bool {
		return a.sources[i].Name() > a.sources[j].Name()
	})

	for _, source := range a.sources {
		stats[source.Name()] = source.Statistics()
	}
	return stats
}
