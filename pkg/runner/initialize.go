package runner

import (
	"net"
	"os"
	"slices"
	"strings"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// initializePassiveEngine creates the passive engine and loads sources etc
func (r *Runner) initializePassiveEngine(providerKeys map[string][]string) {
	// Snapshot credentials and selection once. Workers own fresh adapters, not
	// copies of the global sources or their mutable enumeration state.
	keys := make(map[string][]string, len(providerKeys))
	for name, values := range providerKeys {
		keys[name] = slices.Clone(values)
	}

	for _, source := range passive.NameSourceMap {
		requirement := source.KeyRequirement()
		if requirement == subscraping.RequiredKey || requirement == subscraping.OptionalKey {
			if value := os.Getenv(strings.ToUpper(source.Name()) + "_API_KEY"); value != "" {
				keys[strings.ToLower(source.Name())] = []string{value}
			}
		}
	}

	sources, excluded := slices.Clone(r.options.Sources), slices.Clone(r.options.ExcludeSources)
	all, recursive := r.options.All, r.options.OnlyRecursive
	r.newPassiveAgent = func() *passive.Agent {
		return passive.NewWithProviderConfig(sources, excluded, all, recursive, keys)
	}
	r.passiveAgent = r.newPassiveAgent()
}

// initializeResolver creates the resolver used to resolve the found subdomains
func (r *Runner) initializeResolver() error {
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
