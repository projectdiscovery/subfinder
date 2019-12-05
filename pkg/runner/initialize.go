package runner

import (
	"strings"

	"github.com/projectdiscovery/subfinder/pkg/passive"
	"github.com/projectdiscovery/subfinder/pkg/resolve"
)

// initializePassiveEngine creates the passive engine and loads sources etc
func (r *Runner) initializePassiveEngine() {
	var sources, exclusions []string

	// If there are any sources from CLI, only use them
	// Otherwise, use the yaml file sources
	if r.options.Sources != "" {
		sources = append(sources, strings.Split(r.options.Sources, ",")...)
	} else {
		sources = append(sources, r.options.YAMLConfig.Sources...)
	}

	if r.options.ExcludeSources != "" {
		exclusions = append(exclusions, strings.Split(r.options.ExcludeSources, ",")...)
	} else {
		exclusions = append(exclusions, r.options.YAMLConfig.ExcludeSources...)
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
	} else {
		resolvers = append(resolvers, r.options.YAMLConfig.Resolvers...)
	}
	r.resolverClient.AppendResolversFromSlice(resolvers)
	return nil
}
