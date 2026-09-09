package resolve

import (
	"context"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// DefaultResolvers contains the default list of resolvers known to be good
var DefaultResolvers = []string{
	"1.1.1.1:53",        // Cloudflare primary
	"1.0.0.1:53",        // Cloudflare secondary
	"8.8.8.8:53",        // Google primary
	"8.8.4.4:53",        // Google secondary
	"9.9.9.9:53",        // Quad9 Primary
	"9.9.9.10:53",       // Quad9 Secondary
	"77.88.8.8:53",      // Yandex Primary
	"77.88.8.1:53",      // Yandex Secondary
	"208.67.222.222:53", // OpenDNS Primary
	"208.67.220.220:53", // OpenDNS Secondary
}

// Resolver is a struct for resolving DNS names
type Resolver struct {
	DNSClient   *dnsx.DNSX
	Resolvers   []string
	lookupSlots chan struct{}
}

// WithConcurrencyLimit returns a copy whose pools share a worker and lookup limit.
// The DNS client is shared; the original resolver is unchanged. Nonpositive limits use one slot.
func (r *Resolver) WithConcurrencyLimit(limit int) *Resolver {
	if limit < 1 {
		limit = 1
	}

	bounded := *r
	bounded.lookupSlots = make(chan struct{}, limit)

	return &bounded
}

func (r *Resolver) lookup(ctx context.Context, host string) ([]string, error) {
	if err := r.acquire(ctx); err != nil {
		return nil, err
	}

	if r.lookupSlots != nil {
		defer func() { <-r.lookupSlots }()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// DNSX does not accept a context: an active lookup completes within its own timeout.
	return r.DNSClient.Lookup(host)
}

func (r *Resolver) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if r.lookupSlots == nil {
		return nil
	}

	select {
	case r.lookupSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// New creates a new resolver struct with the default resolvers
func New() *Resolver {
	return &Resolver{
		Resolvers: []string{},
	}
}
