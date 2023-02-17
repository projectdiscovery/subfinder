package passive

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// EnumerateSubdomains wraps EnumerateSubdomainsWithCtx with an empty context
func (a *Agent) EnumerateSubdomains(domain string, proxy string, rateLimit, timeout int, maxEnumTime time.Duration) chan subscraping.Result {
	return a.EnumerateSubdomainsWithCtx(context.Background(), domain, proxy, rateLimit, timeout, maxEnumTime)
}

// EnumerateSubdomainsWithCtx enumerates all the subdomains for a given domain
func (a *Agent) EnumerateSubdomainsWithCtx(ctx context.Context, domain string, proxy string, rateLimit, timeout int, maxEnumTime time.Duration) chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)

		session, err := subscraping.NewSession(domain, proxy, rateLimit, timeout)
		if err != nil {
			results <- subscraping.Result{
				Type: subscraping.Error, Error: fmt.Errorf("could not init passive session for %s: %s", domain, err),
			}
			return
		}

		ctx, cancel := context.WithTimeout(ctx, maxEnumTime)

		wg := &sync.WaitGroup{}
		// Run each source in parallel on the target domain
		for _, runner := range a.sources {
			wg.Add(1)

			go func(source subscraping.Source) {
				for resp := range source.Run(ctx, domain, session) {
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
