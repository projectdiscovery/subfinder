package runner

import (
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
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
	Proxy              string // HTTP proxy
	RateLimit          int    // Maximum number of HTTP requests to send per second
	LocalIP            net.IP // LocalIP is the IP address used as local bind
	LocalIPString      string // LocalIPString is the IP address in string format got from command line

	YAMLConfig ConfigFile // YAMLConfig contains the unmarshalled yaml config file
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources. It has a simple modular architecture and is optimized for speed. subfinder is built for doing one thing only - passive subdomain enumeration, and it does that very well.`)
	createGroup(flagSet, "input", "Target",
		flagSet.StringVar(&options.Domain, "d", "", "Domain to find subdomains for"),
		flagSet.StringVar(&options.DomainsFile, "dL", "", "File containing list of domains to enumerate"),
		flagSet.StringVar(&options.Sources, "sources", "", "Comma separated list of sources to use"),
	)
	createGroup(flagSet, "template", "Template",
		flagSet.IntVar(&options.Threads, "t", 10, "Number of concurrent goroutines for resolving"),
		flagSet.IntVar(&options.Timeout, "timeout", 30, "Seconds to wait before timing out"),
		flagSet.IntVar(&options.MaxEnumerationTime, "max-time", 10, "Minutes to wait for enumeration results"),
		flagSet.BoolVar(&options.ListSources, "ls", false, "List all available sources"),
		flagSet.BoolVar(&options.Recursive, "recursive", false, "Use only recursive subdomain enumeration sources"),
		flagSet.BoolVar(&options.All, "all", false, "Use all sources (slow) for enumeration"),
		flagSet.StringVar(&options.ExcludeSources, "exclude-sources", "", "List of sources to exclude from enumeration"),
	)
	createGroup(flagSet, "filters", "FILTERING",
		flagSet.StringVar(&options.Resolvers, "r", "", "Comma-separated list of resolvers to use"),
		flagSet.StringVar(&options.ResolverList, "rL", "", "Text file containing list of resolvers to use"),
		flagSet.BoolVar(&options.RemoveWildcard, "nW", false, "Remove Wildcard & Dead Subdomains from output"),
		flagSet.StringVar(&options.LocalIPString, "b", "", "IP address to be used as local bind"),
		flagSet.StringVar(&options.Proxy, "proxy", "", "HTTP proxy to use with subfinder"),
	)
	createGroup(flagSet, "config", "Configurations",
		flagSet.StringVar(&options.ConfigFile, "config", "", "Configuration file for API Keys, etc"),
		//flagSet.StringVar(&options.ConfigFile, "config", path.Join(config, "config.yaml"), "Configuration file for API Keys, etc"),
		//flagSet.StringVar(&options.SourceConfigFile, "source-config", path.Join(config, "config.yaml"), "Source Configuration file for API Keys, etc"),
	)
	createGroup(flagSet, "rate-limit", "RATE-LIMIT",
		flagSet.IntVar(&options.RateLimit, "rate-limit", 0, "Maximum number of HTTP requests to send per second"),
	)
	createGroup(flagSet, "output", "Output",
		flagSet.BoolVar(&options.Verbose, "v", false, "Show Verbose output"),
		flagSet.BoolVar(&options.NoColor, "nC", false, "Don't Use colors in output"),
		flagSet.StringVar(&options.OutputFile, "o", "", "File to write output to (optional)"),
		flagSet.StringVar(&options.OutputDirectory, "oD", "", "Directory to write enumeration results to (optional)"),
		flagSet.BoolVar(&options.JSON, "json", false, "Write output in JSON lines Format"),
		flagSet.BoolVar(&options.CaptureSources, "collect-sources", false, "Output host source as array of sources instead of single (first) source"),
		flagSet.BoolVar(&options.JSON, "oJ", false, "Write output in JSON lines Format"),
		flagSet.BoolVar(&options.HostIP, "oI", false, "Write output in Host,IP format"),
		flagSet.BoolVar(&options.Silent, "silent", false, "Show only subdomains in output"),
		flagSet.BoolVar(&options.Version, "version", false, "Show version of subfinder"),
	)
	_ = flagSet.Parse()

	// Default output is stdout
	//	options.Output = os.Stdout

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

	// Check if the application loading with any configuration, then take it
	// Otherwise load the default config data from the code
	if options.ConfigFile != "" {
		gologger.Info().Msgf("loading from file %s", options.ConfigFile)
		options.sourceRunTasks()
	} else {
		gologger.Info().Msg("loading the default")
		options.defaultRunTasks()
	}
	if options.ListSources {
		listSources(options)
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.validateOptions()
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
func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
