package resolve

import (
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

	wildcardIPs map[string]struct{}
}

// HostEntry defines a host with the source
type HostEntry struct {
	Domain string
	Host   string
	Source string
}

// Result contains the result for a host resolution
type Result struct {
	Type   ResultType
	Host   string
	IP     string
	Error  error
	Source string
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
	resolutionPool := &ResolutionPool{
		Resolver:       r,
		Tasks:          make(chan HostEntry),
		Results:        make(chan Result),
		wg:             &sync.WaitGroup{},
		removeWildcard: removeWildcard,
		wildcardIPs:    make(map[string]struct{}),
	}

	go func() {
		for i := 0; i < workers; i++ {
			resolutionPool.wg.Add(1)
			go resolutionPool.resolveWorker()
		}
		resolutionPool.wg.Wait()
		close(resolutionPool.Results)
	}()

	return resolutionPool
}

// InitWildcards inits the wildcard ips array
func (r *ResolutionPool) InitWildcards(domain string) error {
	for i := 0; i < maxWildcardChecks; i++ {
		uid := xid.New().String()

		hosts, _ := r.DNSClient.Lookup(uid + "." + domain)
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
	for task := range r.Tasks {
		if !r.removeWildcard {
			r.Results <- Result{Type: Subdomain, Host: task.Host, IP: "", Source: task.Source}
			continue
		}

		hosts, err := r.DNSClient.Lookup(task.Host)
		if err != nil {
			r.Results <- Result{Type: Error, Host: task.Host, Source: task.Source, Error: err}
			continue
		}

		if len(hosts) == 0 {
			continue
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
			r.Results <- Result{Type: Subdomain, Host: task.Host, IP: hosts[0], Source: task.Source}
		}
	}
	r.wg.Done()
}
