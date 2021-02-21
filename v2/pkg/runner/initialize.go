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

	if r.options.ExcludeSources != "" {
		exclusions = append(exclusions, strings.Split(r.options.ExcludeSources, ",")...)
	} else {
		exclusions = append(exclusions, r.options.YAMLConfig.ExcludeSources...)
	}

	// Use all sources if asked by the user
	if r.options.All {
		sources = append(sources, r.options.YAMLConfig.AllSources...)
	}

	// If only recursive sources are wanted, use them only.
	if r.options.Recursive {
		sources = append(sources, r.options.YAMLConfig.Recursive...)
	}

	// If there are any sources from CLI, only use them
	// Otherwise, use the yaml file sources
	if !r.options.All && !r.options.Recursive {
		if r.options.Sources != "" {
			sources = append(sources, strings.Split(r.options.Sources, ",")...)
		} else {
			sources = append(sources, r.options.YAMLConfig.Sources...)
		}
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

	if r.options.Resolvers != "" {
		resolvers = append(resolvers, strings.Split(r.options.Resolvers, ",")...)
	} else if len(r.options.YAMLConfig.Resolvers) > 0 {
		resolvers = append(resolvers, r.options.YAMLConfig.Resolvers...)
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
