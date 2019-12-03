package runner

import (
	"strings"

	"github.com/subfinder/subfinder/pkg/passive"
	"github.com/subfinder/subfinder/pkg/resolve"
)

// initializePassiveEngine creates the passive engine and loads sources etc
func (r *Runner) initializePassiveEngine() {
	var sources, exclusions []string

	// Append all the sources from YAML and CLI flag
	sources = append(sources, r.options.YAMLConfig.Sources...)
	sources = append(sources, strings.Split(r.options.Sources, ",")...)

	// Append all excluded sources from YAML and CLI flag
	exclusions = append(exclusions, r.options.YAMLConfig.ExcludeSources...)
	exclusions = append(exclusions, strings.Split(r.options.ExcludeSources, ",")...)

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
	// Append all the resolvers read from the config as well as the CLI
	resolvers = append(resolvers, strings.Split(r.options.Resolvers, ",")...)
	resolvers = append(resolvers, r.options.YAMLConfig.Resolvers...)
	r.resolverClient.AppendResolversFromSlice(resolvers)
	return nil
}
