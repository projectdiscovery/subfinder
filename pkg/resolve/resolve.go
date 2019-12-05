package resolve

import (
	"sync"

	"github.com/miekg/dns"
	"github.com/rs/xid"
)

const (
	maxResolveRetries = 5
	maxWildcardChecks = 3
)

// ResolutionPool is a pool of resolvers created for resolving subdomains
// for a given host.
type ResolutionPool struct {
	*Resolver
	Tasks          chan string
	Results        chan Result
	wg             *sync.WaitGroup
	removeWildcard bool

	wildcardIPs map[string]struct{}
}

// Result contains the result for a host resolution
type Result struct {
	Type  ResultType
	Host  string
	IP    string
	Error error
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
		Tasks:          make(chan string),
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

		hosts, err := r.getARecords(uid + "." + domain)
		if err != nil {
			return err
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
			r.Results <- Result{Type: Subdomain, Host: task, IP: ""}
			continue
		}

		hosts, err := r.getARecords(task)
		if err != nil {
			r.Results <- Result{Type: Error, Error: err}
			continue
		}

		if len(hosts) == 0 {
			continue
		}

		for _, host := range hosts {
			// Ignore the host if it exists in wildcard ips map
			if _, ok := r.wildcardIPs[host]; ok {
				continue
			}
		}

		r.Results <- Result{Type: Subdomain, Host: task, IP: hosts[0]}
	}
	r.wg.Done()
}

// getARecords gets all the A records for a given host
func (r *ResolutionPool) getARecords(host string) ([]string, error) {
	var iteration int

	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(host),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
exchange:
	iteration++
	in, err := dns.Exchange(m, r.resolvers[r.rand.Intn(len(r.resolvers))]+":53")
	if err != nil {
		// Retry in case of I/O error
		if iteration <= maxResolveRetries {
			goto exchange
		}
		return nil, err
	}
	// Ignore the error in case we have bad result
	if in != nil && in.Rcode != dns.RcodeSuccess {
		return nil, nil
	}

	var hosts []string
	for _, record := range in.Answer {
		if t, ok := record.(*dns.A); ok {
			hosts = append(hosts, t.A.String())
		}
	}

	return hosts, nil
}
