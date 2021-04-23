package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

const banner = `
               __    _____           __         
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /    
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/ v2.4.8
`

// Version is the current version of subfinder
const Version = `2.4.8`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Print().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Print().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
	gologger.Print().Msgf("By using subfinder, you also agree to the terms of the APIs used.\n\n")
}

// normalRunTasks runs the normal startup tasks
func (options *Options) normalRunTasks() {
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
	}
	options.YAMLConfig = configFile
}

// firstRunTasks runs some housekeeping tasks done
// when the program is ran for the first time
func (options *Options) firstRunTasks() {
	// Create the configuration file and display information
	// about it to the user.
	config := ConfigFile{
		// Use the default list of resolvers by marshaling it to the config
		Resolvers: resolve.DefaultResolvers,
		// Use the default list of passive sources
		Sources: passive.DefaultSources,
		// Use the default list of all passive sources
		AllSources: passive.DefaultAllSources,
		// Use the default list of recursive sources
		Recursive: passive.DefaultRecursiveSources,
	}

	err := config.MarshalWrite(options.ConfigFile)
	if err != nil {
		gologger.Fatal().Msgf("Could not write configuration file to %s: %s\n", options.ConfigFile, err)
	}
	options.YAMLConfig = config

	gologger.Info().Msgf("Configuration file saved to %s\n", options.ConfigFile)
}
