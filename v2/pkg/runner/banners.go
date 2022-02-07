package runner

import (
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

const banner = `
               __    _____           __         
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /    
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/ v2.4.9
`

// Version is the current version of subfinder
const Version = `v2.4.9`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Print().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Print().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
	gologger.Print().Msgf("By using subfinder, you also agree to the terms of the APIs used.\n\n")
}

// sourceRunTasks runs the app with source config
func (options *Options) sourceRunTasks() {
	configFile, err := UnmarshalRead(options.ConfigFile)
	if err != nil {
		gologger.Fatal().Msgf("Could not read configuration file %s: %s\n", options.ConfigFile, err)
	}
	// If we have a different version of subfinder installed
	// previously, use the new iteration of config file.
	if configFile.Version != Version {
		configFile.Sources = passive.DefaultSources
		configFile.AllSources = passive.DefaultAllSources
		configFile.Recursive = passive.DefaultRecursiveSources
		configFile.Version = Version

		err = configFile.MarshalWrite(options.ConfigFile)
		if err != nil {
			gologger.Fatal().Msgf("Could not update configuration file to %s: %s\n", options.ConfigFile, err)
		}
		gologger.Info().Msgf("Configuration file updated to %s\n", options.ConfigFile)
	}
	options.YAMLConfig = configFile
}

// defaultRunTasks runs the app with default configuration
func (options *Options) defaultRunTasks() {
	configFile, err := UnmarshalRead(options.ConfigFile)
	if err != nil && !strings.Contains(err.Error(), goflags.ErrEofYaml.Error()) {
		gologger.Fatal().Msgf("Could not read configuration file %s: %s\n", options.ConfigFile, err)
	}
	configFile.Sources = passive.DefaultSources
	configFile.AllSources = passive.DefaultAllSources
	configFile.Recursive = passive.DefaultRecursiveSources
	configFile.Resolvers = resolve.DefaultResolvers
	options.YAMLConfig = configFile
}
