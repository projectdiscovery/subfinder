package passive

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// EnumerateSubdomains wraps EnumerateSubdomainsWithCtx with an empty context
func (a *Agent) EnumerateSubdomains(domain string, proxy string, rateLimit int, rateLimits map[string]interface{}, timeout int, maxEnumTime time.Duration) chan subscraping.Result {
	return a.EnumerateSubdomainsWithCtx(context.Background(), domain, proxy, rateLimit, rateLimits, timeout, maxEnumTime)
}

// EnumerateSubdomainsWithCtx enumerates all the subdomains for a given domain
func (a *Agent) EnumerateSubdomainsWithCtx(ctx context.Context, domain string, proxy string, rateLimit int, rateLimits map[string]interface{}, timeout int, maxEnumTime time.Duration) chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		multiRateLimiter, err := buildMultiRateLimiter(ctx, a, rateLimit, rateLimits)
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
				ctxWithValue := context.WithValue(ctx, subscraping.CtxSourceArg, source.Name())
				for resp := range source.Run(ctxWithValue, domain, session) {
					results <- resp
				}
				wg.Done()
			}(runner)
		}
		wg.Wait()
		cancel()
	}()
	return results
}

func buildMultiRateLimiter(ctx context.Context, a *Agent, rateLimit int, rateLimits map[string]interface{}) (*ratelimit.MultiLimiter, error) {
	var multiRateLimiter *ratelimit.MultiLimiter
	var err error
	for _, source := range a.sources {
		var rl uint
		if sourceRateLimit, ok := rateLimits[strings.ToLower(source.Name())]; ok {
			rl = sourceRateLimitOrGlobal(rateLimit, sourceRateLimit)
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

func sourceRateLimitOrGlobal(globalRateLimit int, sourceRateLimit interface{}) uint {
	if sourceRateLimitStr, ok := sourceRateLimit.(string); ok {
		sourceRateLimitUint, err := strconv.ParseUint(sourceRateLimitStr, 10, 64)
		if err == nil && sourceRateLimitUint > 0 && sourceRateLimitUint <= math.MaxUint32 {
			return uint(sourceRateLimitUint)
		}
	}
	return uint(globalRateLimit)
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
