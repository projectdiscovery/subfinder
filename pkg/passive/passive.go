package passive

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// EnumerateSubdomains enumerates all the subdomains for a given domain
func (a *Agent) EnumerateSubdomains(domain string, keys subscraping.Keys, timeout int, maxEnumTime time.Duration) chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		session, err := subscraping.NewSession(domain, keys, timeout)
		if err != nil {
			results <- subscraping.Result{Type: subscraping.Error, Error: fmt.Errorf("could not init passive session for %s: %s", domain, err)}
		}

		ctx, cancel := context.WithTimeout(context.Background(), maxEnumTime)

		wg := &sync.WaitGroup{}
		// Run each source in parallel on the target domain
		for source, runner := range a.sources {
			wg.Add(1)

			go func(source string, runner subscraping.Source) {
				for resp := range runner.Run(ctx, domain, session) {
					results <- resp
				}
				wg.Done()
			}(source, runner)
		}
		wg.Wait()

		close(results)
		cancel()
	}()

	return results
}
