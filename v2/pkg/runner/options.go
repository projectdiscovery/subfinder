package runner

import (
	"flag"
	"io"
	"os"
	"path"
	"reflect"
	"strings"

	"github.com/projectdiscovery/gologger"
)

// Options contains the configuration options for tuning
// the subdomain enumeration process.
type Options struct {
	Verbose            bool   // Verbose flag indicates whether to show verbose output or not
	NoColor            bool   // No-Color disables the colored output
	JSON               bool   // JSON specifies whether to use json for output format or text file
	HostIP             bool   // HostIP specifies whether to write subdomains in host:ip format
	Silent             bool   // Silent suppresses any extra text and only writes subdomains to screen
	ListSources        bool   // ListSources specifies whether to list all available sources
	RemoveWildcard     bool   // RemoveWildcard specifies whether to remove potential wildcard or dead subdomains from the results.
	CaptureSources     bool   // CaptureSources specifies whether to save all sources that returned a specific domains or just the first source
	Stdin              bool   // Stdin specifies whether stdin input was given to the process
	Version            bool   // Version specifies if we should just show version and exit
	Recursive          bool   // Recursive specifies whether to use only recursive subdomain enumeration sources
	All                bool   // All specifies whether to use all (slow) sources.
	Threads            int    // Thread controls the number of threads to use for active enumerations
	Timeout            int    // Timeout is the seconds to wait for sources to respond
	MaxEnumerationTime int    // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
	Domain             string // Domain is the domain to find subdomains for
	DomainsFile        string // DomainsFile is the file containing list of domains to find subdomains for
	Output             io.Writer
	OutputFile         string // Output is the file to write found subdomains to.
	OutputDirectory    string // OutputDirectory is the directory to write results to in case list of domains is given
	Sources            string // Sources contains a comma-separated list of sources to use for enumeration
	ExcludeSources     string // ExcludeSources contains the comma-separated sources to not include in the enumeration process
	Resolvers          string // Resolvers is the comma-separated resolvers to use for enumeration
	ResolverList       string // ResolverList is a text file containing list of resolvers to use for enumeration
	ConfigFile         string // ConfigFile contains the location of the config file

	YAMLConfig ConfigFile // YAMLConfig contains the unmarshalled yaml config file
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	config, err := GetConfigDirectory()
	if err != nil {
		// This should never be reached
		gologger.Fatal().Msgf("Could not get user home: %s\n", err)
	}

	flag.BoolVar(&options.Verbose, "v", false, "Show Verbose output")
	flag.BoolVar(&options.NoColor, "nC", false, "Don't Use colors in output")
	flag.IntVar(&options.Threads, "t", 10, "Number of concurrent goroutines for resolving")
	flag.IntVar(&options.Timeout, "timeout", 30, "Seconds to wait before timing out")
	flag.IntVar(&options.MaxEnumerationTime, "max-time", 10, "Minutes to wait for enumeration results")
	flag.StringVar(&options.Domain, "d", "", "Domain to find subdomains for")
	flag.StringVar(&options.DomainsFile, "dL", "", "File containing list of domains to enumerate")
	flag.StringVar(&options.OutputFile, "o", "", "File to write output to (optional)")
	flag.StringVar(&options.OutputDirectory, "oD", "", "Directory to write enumeration results to (optional)")
	flag.BoolVar(&options.JSON, "json", false, "Write output in JSON lines Format")
	flag.BoolVar(&options.CaptureSources, "collect-sources", false, "Output host source as array of sources instead of single (first) source")
	flag.BoolVar(&options.JSON, "oJ", false, "Write output in JSON lines Format")
	flag.BoolVar(&options.HostIP, "oI", false, "Write output in Host,IP format")
	flag.BoolVar(&options.Silent, "silent", false, "Show only subdomains in output")
	flag.BoolVar(&options.Recursive, "recursive", false, "Use only recursive subdomain enumeration sources")
	flag.BoolVar(&options.All, "all", false, "Use all sources (slow) for enumeration")
	flag.StringVar(&options.Sources, "sources", "", "Comma separated list of sources to use")
	flag.BoolVar(&options.ListSources, "ls", false, "List all available sources")
	flag.StringVar(&options.ExcludeSources, "exclude-sources", "", "List of sources to exclude from enumeration")
	flag.StringVar(&options.Resolvers, "r", "", "Comma-separated list of resolvers to use")
	flag.StringVar(&options.ResolverList, "rL", "", "Text file containing list of resolvers to use")
	flag.BoolVar(&options.RemoveWildcard, "nW", false, "Remove Wildcard & Dead Subdomains from output")
	flag.StringVar(&options.ConfigFile, "config", path.Join(config, "config.yaml"), "Configuration file for API Keys, etc")
	flag.BoolVar(&options.Version, "version", false, "Show version of subfinder")
	flag.Parse()

	// Default output is stdout
	options.Output = os.Stdout

	// Check if stdin pipe was given
	options.Stdin = hasStdin()

	// Read the inputs and configure the logging
	options.configureOutput()

	// Show the user the banner
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Check if the config file exists. If not, it means this is the
	// first run of the program. Show the first run notices and initialize the config file.
	// Else show the normal banners and read the yaml fiile to the config
	if !CheckConfigExists(options.ConfigFile) {
		options.firstRunTasks()
	} else {
		options.normalRunTasks()
	}

	if options.ListSources {
		listSources(options)
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err = options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}

func listSources(options *Options) {
	gologger.Info().Msgf("Current list of available sources. [%d]\n", len(options.YAMLConfig.AllSources))
	gologger.Info().Msgf("Sources marked with an * needs key or token in order to work.\n")
	gologger.Info().Msgf("You can modify %s to configure your keys / tokens.\n\n", options.ConfigFile)

	keys := options.YAMLConfig.GetKeys()
	needsKey := make(map[string]interface{})
	keysElem := reflect.ValueOf(&keys).Elem()
	for i := 0; i < keysElem.NumField(); i++ {
		needsKey[strings.ToLower(keysElem.Type().Field(i).Name)] = keysElem.Field(i).Interface()
	}

	for _, source := range options.YAMLConfig.AllSources {
		message := "%s\n"
		if _, ok := needsKey[source]; ok {
			message = "%s *\n"
		}
		gologger.Silent().Msgf(message, source)
	}
}
