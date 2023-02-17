package runner

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/projectdiscovery/utils/file"
	"github.com/projectdiscovery/utils/log"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

var (
	defaultConfigLocation         = filepath.Join(userHomeDir(), ".config/subfinder/config.yaml")
	defaultProviderConfigLocation = filepath.Join(userHomeDir(), ".config/subfinder/provider-config.yaml")
)

// Options contains the configuration options for tuning
// the subdomain enumeration process.
type Options struct {
	Verbose            bool                // Verbose flag indicates whether to show verbose output or not
	NoColor            bool                // NoColor disables the colored output
	JSON               bool                // JSON specifies whether to use json for output format or text file
	HostIP             bool                // HostIP specifies whether to write subdomains in host:ip format
	Silent             bool                // Silent suppresses any extra text and only writes subdomains to screen
	ListSources        bool                // ListSources specifies whether to list all available sources
	RemoveWildcard     bool                // RemoveWildcard specifies whether to remove potential wildcard or dead subdomains from the results.
	CaptureSources     bool                // CaptureSources specifies whether to save all sources that returned a specific domains or just the first source
	Stdin              bool                // Stdin specifies whether stdin input was given to the process
	Version            bool                // Version specifies if we should just show version and exit
	OnlyRecursive      bool                // Recursive specifies whether to use only recursive subdomain enumeration sources
	All                bool                // All specifies whether to use all (slow) sources.
	Statistics         bool                // Statistics specifies whether to report source statistics
	Threads            int                 // Threads controls the number of threads to use for active enumerations
	Timeout            int                 // Timeout is the seconds to wait for sources to respond
	MaxEnumerationTime int                 // MaxEnumerationTime is the maximum amount of time in minutes to wait for enumeration
	Domain             goflags.StringSlice // Domain is the domain to find subdomains for
	DomainsFile        string              // DomainsFile is the file containing list of domains to find subdomains for
	Output             io.Writer
	OutputFile         string              // Output is the file to write found subdomains to.
	OutputDirectory    string              // OutputDirectory is the directory to write results to in case list of domains is given
	Sources            goflags.StringSlice `yaml:"sources,omitempty"`         // Sources contains a comma-separated list of sources to use for enumeration
	ExcludeSources     goflags.StringSlice `yaml:"exclude-sources,omitempty"` // ExcludeSources contains the comma-separated sources to not include in the enumeration process
	Resolvers          goflags.StringSlice `yaml:"resolvers,omitempty"`       // Resolvers is the comma-separated resolvers to use for enumeration
	ResolverList       string              // ResolverList is a text file containing list of resolvers to use for enumeration
	Config             string              // Config contains the location of the config file
	ProviderConfig     string              // ProviderConfig contains the location of the provider config file
	Proxy              string              // HTTP proxy
	RateLimit          int                 // Maximum number of HTTP requests to send per second
	ExcludeIps         bool
	Match              goflags.StringSlice
	Filter             goflags.StringSlice
	matchRegexes       []*regexp.Regexp
	filterRegexes      []*regexp.Regexp
	ResultCallback     OnResultCallback // OnResult callback
}

// OnResultCallback (hostResult)
type OnResultCallback func(result *resolve.HostEntry)

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	logutil.DisableDefaultLogger()
	// Seed default random number generator
	rand.Seed(time.Now().UnixNano())

	// Migrate config to provider config
	if fileutil.FileExists(defaultConfigLocation) && !fileutil.FileExists(defaultProviderConfigLocation) {
		gologger.Info().Msgf("Detected old '%s' config file, trying to migrate providers to '%s'\n", defaultConfigLocation, defaultProviderConfigLocation)
		if err := migrateToProviderConfig(defaultConfigLocation, defaultProviderConfigLocation); err != nil {
			gologger.Warning().Msgf("Could not migrate providers from existing config '%s' to provider config '%s': %s\n", defaultConfigLocation, defaultProviderConfigLocation, err)
		} else {
			// cleanup the existing config file post migration
			_ = os.Remove(defaultConfigLocation)
			gologger.Info().Msgf("Migration successful from '%s' to '%s'.\n", defaultConfigLocation, defaultProviderConfigLocation)
		}
	}

	options := &Options{}

	var err error
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Subfinder is a subdomain discovery tool that discovers subdomains for websites by using passive online sources.`)

	createGroup(flagSet, "input", "Input",
		flagSet.StringSliceVarP(&options.Domain, "domain", "d", []string{}, "domains to find subdomains for", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.DomainsFile, "list", "dL", "", "file containing list of domains for subdomain discovery"),
	)

	createGroup(flagSet, "source", "Source",
		flagSet.StringSliceVarP(&options.Sources, "sources", "s", []string{}, "specific sources to use for discovery (-s crtsh,github). Use -ls to display all available sources.", goflags.NormalizedStringSliceOptions),
		flagSet.BoolVar(&options.OnlyRecursive, "recursive", false, "use only sources that can handle subdomains recursively (e.g. subdomain.domain.tld vs domain.tld)"),
		flagSet.BoolVar(&options.All, "all", false, "use all sources for enumeration (slow)"),
		flagSet.StringSliceVarP(&options.ExcludeSources, "exclude-sources", "es", []string{}, "sources to exclude from enumeration (-es alienvault,zoomeye)", goflags.NormalizedStringSliceOptions),
	)

	createGroup(flagSet, "filter", "Filter",
		flagSet.StringSliceVarP(&options.Match, "match", "m", []string{}, "subdomain or list of subdomain to match (file or comma separated)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.Filter, "filter", "f", []string{}, " subdomain or list of subdomain to filter (file or comma separated)", goflags.FileNormalizedStringSliceOptions),
	)

	createGroup(flagSet, "rate-limit", "Rate-limit",
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 0, "maximum number of http requests to send per second"),
		flagSet.IntVar(&options.Threads, "t", 10, "number of concurrent goroutines for resolving (-active only)"),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to"),
		flagSet.BoolVarP(&options.JSON, "json", "oJ", false, "write output in JSONL(ines) format"),
		flagSet.StringVarP(&options.OutputDirectory, "output-dir", "oD", "", "directory to write output (-dL only)"),
		flagSet.BoolVarP(&options.CaptureSources, "collect-sources", "cs", false, "include all sources in the output (-json only)"),
		flagSet.BoolVarP(&options.HostIP, "ip", "oI", false, "include host IP in output (-active only)"),
	)

	createGroup(flagSet, "configuration", "Configuration",
		flagSet.StringVar(&options.Config, "config", defaultConfigLocation, "flag config file"),
		flagSet.StringVarP(&options.ProviderConfig, "provider-config", "pc", defaultProviderConfigLocation, "provider config file"),
		flagSet.StringSliceVar(&options.Resolvers, "r", []string{}, "comma separated list of resolvers to use", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.ResolverList, "rlist", "rL", "", "file containing list of resolvers to use"),
		flagSet.BoolVarP(&options.RemoveWildcard, "active", "nW", false, "display active subdomains only"),
		flagSet.StringVar(&options.Proxy, "proxy", "", "http proxy to use with subfinder"),
		flagSet.BoolVarP(&options.ExcludeIps, "exclude-ip", "ei", false, "exclude IPs from the list of domains"),
	)

	createGroup(flagSet, "debug", "Debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "show only subdomains in output"),
		flagSet.BoolVar(&options.Version, "version", false, "show version of subfinder"),
		flagSet.BoolVar(&options.Verbose, "v", false, "show verbose output"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable color in output"),
		flagSet.BoolVarP(&options.ListSources, "list-sources", "ls", false, "list all available sources"),
		flagSet.BoolVar(&options.Statistics, "stats", false, "report source statistics"),
	)

	createGroup(flagSet, "optimization", "Optimization",
		flagSet.IntVar(&options.Timeout, "timeout", 30, "seconds to wait before timing out"),
		flagSet.IntVar(&options.MaxEnumerationTime, "max-time", 10, "minutes to wait for enumeration results"),
	)

	if err := flagSet.Parse(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if options.Config != defaultConfigLocation {
		// An empty source file is not a fatal error
		if err := flagSet.MergeConfigFile(options.Config); err != nil && !errors.Is(err, io.EOF) {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	// Default output is stdout
	options.Output = os.Stdout

	// Check if stdin pipe was given
	options.Stdin = fileutil.HasStdin()

	// Read the inputs and configure the logging
	options.configureOutput()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	options.preProcessOptions()

	if !options.Silent {
		showBanner()
	}

	// Check if the application loading with any provider configuration, then take it
	// Otherwise load the default provider config
	if fileutil.FileExists(options.ProviderConfig) {
		gologger.Info().Msgf("Loading provider config from '%s'", options.ProviderConfig)
		options.loadProvidersFrom(options.ProviderConfig)
	} else {
		gologger.Info().Msgf("Loading provider config from the default location: '%s'", defaultProviderConfigLocation)
		options.loadProvidersFrom(defaultProviderConfigLocation)
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

// loadProvidersFrom runs the app with source config
func (options *Options) loadProvidersFrom(location string) {
	// todo: move elsewhere
	if len(options.Resolvers) == 0 {
		options.Resolvers = resolve.DefaultResolvers
	}

	// We skip bailing out if file doesn't exist because we'll create it
	// at the end of options parsing from default via goflags.
	if err := UnmarshalFrom(location); isFatalErr(err) && !errors.Is(err, os.ErrNotExist) {
		gologger.Fatal().Msgf("Could not read providers from '%s': %s\n", location, err)
	}
}

func migrateToProviderConfig(defaultConfigLocation, defaultProviderLocation string) error {
	configs, err := unMarshalToLowerCaseMap(defaultConfigLocation)
	if err != nil {
		return err
	}

	sourcesRequiringApiKeysMap := make(map[string][]string)
	for _, source := range passive.AllSources {
		if source.NeedsKey() {
			sourceName := strings.ToLower(source.Name())
			if sourceKeys, ok := configs[sourceName]; ok {
				sourcesRequiringApiKeysMap[sourceName] = sourceKeys
			} else {
				sourcesRequiringApiKeysMap[sourceName] = []string{}
			}
		}
	}

	return CreateProviderConfigYAML(defaultProviderLocation, sourcesRequiringApiKeysMap)
}

func unMarshalToLowerCaseMap(defaultConfigLocation string) (map[string][]string, error) {
	defaultConfigFile, err := os.Open(defaultConfigLocation)
	if err != nil {
		return nil, err
	}
	defer defaultConfigFile.Close()

	configs := map[string][]string{}
	if err := yaml.NewDecoder(defaultConfigFile).Decode(configs); isFatalErr(err) {
		return nil, err
	}

	for k, v := range configs {
		configs[strings.ToLower(k)] = v
	}
	return configs, nil
}

func isFatalErr(err error) bool {
	return err != nil && !errors.Is(err, io.EOF)
}

func listSources(options *Options) {
	gologger.Info().Msgf("Current list of available sources. [%d]\n", len(passive.AllSources))
	gologger.Info().Msgf("Sources marked with an * need key(s) or token(s) to work.\n")
	gologger.Info().Msgf("You can modify '%s' to configure your keys/tokens.\n\n", options.ProviderConfig)

	for _, source := range passive.AllSources {
		message := "%s\n"
		sourceName := source.Name()
		if source.NeedsKey() {
			message = "%s *\n"
		}
		gologger.Silent().Msgf(message, sourceName)
	}
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}

func (options *Options) preProcessOptions() {
	for i, domain := range options.Domain {
		options.Domain[i], _ = sanitize(domain)
	}
}

func userHomeDir() string {
	usr, err := user.Current()
	if err != nil {
		gologger.Fatal().Msgf("Could not get user home directory: %s\n", err)
	}
	return usr.HomeDir
}
