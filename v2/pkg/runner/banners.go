package runner

import (
	"errors"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

const banner = `
               __    _____           __         
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /    
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/ v2.5.2
`

// Version is the current version of subfinder
const Version = `v2.5.2`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Print().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Print().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
	gologger.Print().Msgf("By using subfinder, you also agree to the terms of the APIs used.\n\n")
}

// loadProvidersFrom runs the app with source config
func (options *Options) loadProvidersFrom(location string) {
	if len(options.AllSources) == 0 {
		options.AllSources = passive.DefaultAllSources
	}
	if len(options.Recursive) == 0 {
		options.Recursive = passive.DefaultRecursiveSources
	}
	// todo: move elsewhere
	if len(options.Resolvers) == 0 {
		options.Recursive = resolve.DefaultResolvers
	}
	if len(options.Sources) == 0 {
		options.Sources = passive.DefaultSources
	}

	options.Providers = &Providers{}
	// We skip bailing out if file doesn't exist because we'll create it
	// at the end of options parsing from default via goflags.
	if err := options.Providers.UnmarshalFrom(location); isFatalErr(err) && !errors.Is(err, os.ErrNotExist) {
		gologger.Fatal().Msgf("Could not read providers from %s: %s\n", location, err)
	}
}
