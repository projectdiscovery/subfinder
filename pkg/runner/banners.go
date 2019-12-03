package runner

import (
	"github.com/subfinder/subfinder/pkg/log"
	"github.com/subfinder/subfinder/pkg/resolve"
)

const banner = `
        _     __ _         _         
____  _| |__ / _(_)_ _  __| |___ _ _ 
(_-< || | '_ \  _| | ' \/ _  / -_) '_|
/__/\_,_|_.__/_| |_|_||_\__,_\___|_| v2
`

// showBanner is used to show the banner to the user
func showBanner() {
	log.Printf("%s\n", banner)
	log.Printf("\t\tprojectdiscovery.io\n\n")
}

func showNotice() {
	log.Labelf("Use with caution. You are responsible for your actions\n")
	log.Labelf("Developers assume no liability and are not responsible for any misuse or damage.\n")
	log.Labelf("By using subfinder, you also agree to the terms of the APIs used.\n\n")
}

// normalRunTasks runs the normal startup tasks
func (options *Options) normalRunTasks() {
	configFile := ConfigFile{}
	err := configFile.UnmarshalRead(options.ConfigFile)
	if err != nil {
		log.Fatalf("Could not read configuration file %s: %s\n", options.ConfigFile, err)
	}
	options.YAMLConfig = configFile
}

// firstRunTasks runs some housekeeping tasks done
// when the program is ran for the first time
func (options *Options) firstRunTasks() {
	// Unauthorized use text
	showNotice()

	// Create the configuration file and display information
	// about it to the user.
	config := ConfigFile{
		// Use the default list of resolvers by marshalling it to the config
		Resolvers: resolve.DefaultResolvers,
	}

	err := config.MarshalWrite(options.ConfigFile)
	if err != nil {
		log.Fatalf("Could not write configuration file to %s: %s\n", options.ConfigFile, err)
	}
	options.YAMLConfig = config

	log.Infof("Configuration file saved to %s\n", options.ConfigFile)
}
