//
// state.go : Contains current program state
// Written By :  @codingo (Michael)
//				 @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package helper

import (
	"os"
)

// State holds the State read in from the CLI
type State struct {
	Color         bool     // Whether to use color or not
	Threads       int      // Number of threads to use
	Timeout       int      // Timeout for requests to different passive sources
	Verbose       bool     // Show verbose information
	Domain        string   // Domain name to find subdomains for
	Recursive     bool     // Whether perform recursive subdomain discovery or not
	Output        string   // Name of output file
	Alive         bool     // Get only alive subdomains (x - no wildcards :-))
	IsJSON        bool     // Provide JSON output file
	Wordlist      string   // Wordlist file for subdomains bruteforcing
	Bruteforce    bool     // Flag to decide whether to bruteforce or not
	WildcardIP    []string // Wildcard IP Structure
	IsWildcard    bool     // Does the host has wildcard subdomains, if yes parse them carefully
	Sources       string   // Comma separated list of sources to use
	Silent        bool     // Show only silent output or not
	FinalResults  []string // Contains final bruteforcing results
	SetConfig     string   // Used for changing the current configuration file details
	SetSetting    string   // Used for passing custom configuration to the application
	DomainList    string   // List of domains to find subdomains for
	OutputDir     string   // Directory to output results to if domain list is used
	LoadResolver  []string // Slice of resolvers to use
	ComResolver   string   // Comma-separated list of resolvers to use
	ListResolver  string   // File to load resolvers from
	AquatoneJSON  bool     // Use aquatone style json format
	ExcludeSource string   // Sources to exclude
	NoPassive     bool     // Do not perform passive enumeration
	OutputHandle  *os.File // Handle to the output file used for output buffering

	CurrentSettings Setting // Current application settings
	ConfigState     Config  // Current configuration file state
}

// Config contains api keys for different sources
type Config struct {
	VirustotalAPIKey string `json:"virustotalApikey"` // Virustotal API Key

	PassivetotalUsername string `json:"passivetotalUsername"` // PassiveTotal Username (Email Address)
	PassivetotalKey      string `json:"passivetotalKey"`      // PassiveTotal api key

	SecurityTrailsKey string `json:"securitytrailsKey"` // SecurityTrails api key

	RiddlerEmail    string `json:"riddlerEmail"`    // Riddler Email
	RiddlerPassword string `json:"riddlerPassword"` // Riddler Password

	CensysUsername string `json:"censysUsername"` // Censys Username
	CensysSecret   string `json:"censysSecret"`   // Censys API Key

	ShodanAPIKey string `json:"shodanApiKey"` // Shodan API Key
}

// Setting contains settings for sources
type Setting struct {
	CensysPages    string // Censys pages to check. For All, use "all"
	AskPages       string // Ask search pages to check
	BaiduPages     string // Ask search pages to check
	BingPages      string // Ask search pages to check
	DogpilePages   string // Dogpile search pages to check
	YahooPages     string // Yahoo search pages to check
	ShodanPages    string // Shodan search pages to check
	GoogleterPages string // Googleter
}

// InitializeSettings sets default settings value
func InitializeSettings() (setting *Setting) {
	var settings Setting

	settings.CensysPages = "10" // Default is 10 pages. Strikes a fine balance

	settings.AskPages = "15"
	settings.BaiduPages = "5"
	settings.BingPages = "50"
	settings.DogpilePages = "16"
	settings.YahooPages = "10"
	settings.ShodanPages = "10"
	settings.GoogleterPages = "30"
	return &settings
}

// InitState initializes the default state
func InitState() (state *State) {

	// Read the configuration file and ignore errors
	config, _ := ReadConfigFile()

	setting := InitializeSettings()

	return &State{true, 10, 180, false, "", false, "", false, false, "", false, []string{}, true, "", false, []string{}, "", "", "", "", []string{}, "", "", false, "", false, nil, *setting, *config}
}
