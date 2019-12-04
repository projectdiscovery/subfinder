package passive

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/subfinder/subfinder/pkg/subscraping"
)

// EnumerateSubdomains enumerates all the subdomains for a given domain
func (a *Agent) EnumerateSubdomains(domain string, keys subscraping.Keys, timeout, maxEnumTime int) chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		session, err := subscraping.NewSession(domain, keys, timeout)
		if err != nil {
			results <- subscraping.Result{Type: subscraping.Error, Error: fmt.Errorf("could not init passive session for %s: %s", domain, err)}
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(maxEnumTime)*time.Second)

		wg := &sync.WaitGroup{}
		// Run each source in parallel on the target domain
		for _, runner := range a.sources {
			wg.Add(1)

			go func(runner subscraping.Source) {
				for resp := range runner.Run(ctx, domain, session) {
					results <- resp
				}
				wg.Done()
			}(runner)
		}
		wg.Wait()

		close(results)
		cancel()
	}()

	return results
}
