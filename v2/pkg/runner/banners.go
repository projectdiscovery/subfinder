package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

const banner = `
        _     __ _         _
____  _| |__ / _(_)_ _  __| |___ _ _
(_-< || | '_ \  _| | ' \/ _  / -_) '_|
/__/\_,_|_.__/_| |_|_||_\__,_\___|_| v2.4.5
`

// Version is the current version of subfinder
const Version = `2.4.5`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Printf("%s\n", banner)
	gologger.Printf("\t\tprojectdiscovery.io\n\n")

	gologger.Labelf("Use with caution. You are responsible for your actions\n")
	gologger.Labelf("Developers assume no liability and are not responsible for any misuse or damage.\n")
	gologger.Labelf("By using subfinder, you also agree to the terms of the APIs used.\n\n")
}

// normalRunTasks runs the normal startup tasks
func (options *Options) normalRunTasks() {
	configFile, err := UnmarshalRead(options.ConfigFile)
	if err != nil {
		gologger.Fatalf("Could not read configuration file %s: %s\n", options.ConfigFile, err)
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
			gologger.Fatalf("Could not update configuration file to %s: %s\n", options.ConfigFile, err)
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
		gologger.Fatalf("Could not write configuration file to %s: %s\n", options.ConfigFile, err)
	}
	options.YAMLConfig = config

	gologger.Infof("Configuration file saved to %s\n", options.ConfigFile)
}
