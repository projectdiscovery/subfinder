// 
// state.go : Contains current program state
// Written By :  @codingo (Michael)
//				 @ice3man (Nizamul Rana)
// 
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package helper

// Holds the State read in from the CLI
type State struct {
	Color   		bool		// Whether to use color or not
	Threads 		int 		// Number of threads to use
	Verbose 		bool 		// Show verbose information
	Domain  		string		// Domain name to find subdomains for
	Recursive 		bool		// Whether perform recursive subdomain discovery or not

	ConfigState  	Config		// Current configuration file state
}

type Config struct {
	VirustotalAPIKey	string	`json:"virustotalapikey"`		// Virustotal API Key
}

func InitState() (state State, err error) {

	// Read the configuration file
	config, err := ReadConfigFile()
	if err != nil {
		return state, err
	}

	return State{true, 10, false, "", false, *config}, nil
}
