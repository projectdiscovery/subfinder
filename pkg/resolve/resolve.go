package resolve

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/xid"
)

const (
	maxWildcardChecks = 3
)

// ResolutionPool is a pool of resolvers created for resolving subdomains
// for a given host.
type ResolutionPool struct {
	*Resolver
	Tasks          chan HostEntry
	Results        chan Result
	wg             *sync.WaitGroup
	removeWildcard bool
	ctx            context.Context

	wildcardIPs map[string]struct{}
}

// HostEntry defines a host with the source
type HostEntry struct {
	Domain              string
	Host                string
	Source              string
	WildcardCertificate bool
}

// Result contains the result for a host resolution
type Result struct {
	Type                ResultType
	Host                string
	IP                  string
	Error               error
	Source              string
	WildcardCertificate bool
}

// ResultType is the type of result found
type ResultType int

// Types of data result can return
const (
	Subdomain ResultType = iota
	Error
)

// NewResolutionPool creates a pool of resolvers for resolving subdomains of a given domain
func (r *Resolver) NewResolutionPool(workers int, removeWildcard bool) *ResolutionPool {
	return r.NewResolutionPoolWithCtx(context.Background(), workers, removeWildcard)
}

// NewResolutionPoolWithCtx creates a pool that stops on cancellation.
// Producers must also observe ctx when sending Tasks, and close Tasks when finished.
func (r *Resolver) NewResolutionPoolWithCtx(ctx context.Context, workers int, removeWildcard bool) *ResolutionPool {
	resolutionPool := &ResolutionPool{
		ctx:            ctx,
		Resolver:       r,
		Tasks:          make(chan HostEntry),
		Results:        make(chan Result),
		wg:             &sync.WaitGroup{},
		removeWildcard: removeWildcard,
		wildcardIPs:    make(map[string]struct{}),
	}

	go func() {
		if r.lookupSlots != nil {
			resolutionPool.dispatch(workers)
		} else {
			for range workers {
				resolutionPool.wg.Add(1)
				go resolutionPool.resolveWorker()
			}
		}

		resolutionPool.wg.Wait()

		close(resolutionPool.Results)
	}()

	return resolutionPool
}

// InitWildcards inits the wildcard ips array
func (r *ResolutionPool) InitWildcards(domain string) error {
	for range maxWildcardChecks {
		uid := xid.New().String()

		hosts, _ := r.lookup(r.ctx, uid+"."+domain)
		if err := r.ctx.Err(); err != nil {
			return err
		}

		if len(hosts) == 0 {
			return fmt.Errorf("%s is not a wildcard domain", domain)
		}

		// Append all wildcard ips found for domains
		for _, host := range hosts {
			r.wildcardIPs[host] = struct{}{}
		}
	}

	return nil
}

func (r *ResolutionPool) resolveWorker() {
	defer r.wg.Done()

	for {
		var task HostEntry
		select {
		case <-r.ctx.Done():
			return
		case next, ok := <-r.Tasks:
			if !ok {
				return
			}

			task = next
		}

		r.resolveTask(task)
	}
}

// dispatch reserves capacity before starting a worker, so separate domain pools
// do not each park a full set of workers waiting for the shared DNS limit.
func (r *ResolutionPool) dispatch(workers int) {
	if workers < 1 {
		return
	}

	localSlots := make(chan struct{}, workers)

	for {
		select {
		case <-r.ctx.Done():
			return
		case task, ok := <-r.Tasks:
			if !ok {
				return
			}

			select {
			case localSlots <- struct{}{}:
			case <-r.ctx.Done():
				return
			}

			if err := r.acquire(r.ctx); err != nil {
				return
			}

			r.wg.Add(1)

			go func() {
				defer r.wg.Done()
				defer func() {
					<-r.lookupSlots
					<-localSlots
				}()

				r.resolveTask(task)
			}()
		}
	}
}

func (r *ResolutionPool) resolveTask(task HostEntry) {
	if r.ctx.Err() != nil {
		return
	}

	if !r.removeWildcard {
		r.sendResult(Result{Type: Subdomain, Host: task.Host, IP: "", Source: task.Source, WildcardCertificate: task.WildcardCertificate})

		return
	}

	// A bounded pool already holds its slot until this result is delivered.
	hosts, err := r.DNSClient.Lookup(task.Host)
	if err != nil {
		r.sendResult(Result{Type: Error, Host: task.Host, Source: task.Source, Error: err, WildcardCertificate: task.WildcardCertificate})

		return
	}

	if len(hosts) == 0 {
		return
	}

	var skip bool
	for _, host := range hosts {
		// Ignore the host if it exists in wildcard ips map
		if _, ok := r.wildcardIPs[host]; ok {
			skip = true

			break
		}
	}

	if !skip {
		r.sendResult(Result{Type: Subdomain, Host: task.Host, IP: hosts[0], Source: task.Source, WildcardCertificate: task.WildcardCertificate})
	}
}

func (r *ResolutionPool) sendResult(result Result) {
	if r.ctx.Err() != nil {
		return
	}

	select {
	case r.Results <- result:
	case <-r.ctx.Done():
	}
}
