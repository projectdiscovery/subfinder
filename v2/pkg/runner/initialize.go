package runner

import (
	"strings"

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
	r.resolverClient = resolve.New()

	// If the file has been provided, read resolvers from the file
	if r.options.ResolverList != "" {
		err := r.resolverClient.AppendResolversFromFile(r.options.ResolverList)
		if err != nil {
			return err
		}
	}

	var resolvers []string

	if r.options.Resolvers != "" {
		resolvers = append(resolvers, strings.Split(r.options.Resolvers, ",")...)
	} else if len(r.options.YAMLConfig.Resolvers) > 0 {
		resolvers = append(resolvers, r.options.YAMLConfig.Resolvers...)
	} else {
		resolvers = append(resolvers, resolve.DefaultResolvers...)
	}

	r.resolverClient.AppendResolversFromSlice(resolvers)

	return nil
}
