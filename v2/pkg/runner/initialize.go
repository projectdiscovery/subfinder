package runner

import (
	"net"
	"strings"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

// initializePassiveEngine creates the passive engine and loads sources etc
func (r *Runner) initializePassiveEngine() {
	var sources, exclusions []string

	if len(r.options.ExcludeSources) > 0 {
		exclusions = r.options.ExcludeSources
	}

	switch {
	// Use all sources if asked by the user
	case r.options.All:
		sources = append(sources, r.options.AllSources...)
	// If only recursive sources are wanted, use them only.
	case r.options.OnlyRecursive:
		sources = append(sources, r.options.Recursive...)
	// Otherwise, use the CLI/YAML sources
	default:
		sources = append(sources, r.options.Sources...)
	}

	r.passiveAgent = passive.New(sources, exclusions)
}

// initializeActiveEngine creates the resolver used to resolve the found subdomains
func (r *Runner) initializeActiveEngine() error {
	var resolvers []string

	// If the file has been provided, read resolvers from the file
	if r.options.ResolverList != "" {
		var err error
		resolvers, err = loadFromFile(r.options.ResolverList)
		if err != nil {
			return err
		}
	}

	if len(r.options.Resolvers) > 0 {
		resolvers = append(resolvers, r.options.Resolvers...)
	} else {
		resolvers = append(resolvers, resolve.DefaultResolvers...)
	}

	// Add default 53 UDP port if missing
	for i, resolver := range resolvers {
		if !strings.Contains(resolver, ":") {
			resolvers[i] = net.JoinHostPort(resolver, "53")
		}
	}

	r.resolverClient = resolve.New()
	var err error
	r.resolverClient.DNSClient, err = dnsx.New(dnsx.Options{BaseResolvers: resolvers, MaxRetries: 5})
	if err != nil {
		return nil
	}

	return nil
}
