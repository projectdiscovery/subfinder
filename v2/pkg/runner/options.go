package runner

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v3"
)

var (
	defaultConfigLocation         = filepath.Join(userHomeDir(), ".config/subfinder/config.yaml")
	defaultProviderConfigLocation = filepath.Join(userHomeDir(), ".config/subfinder/provider-config.yaml")
)

// Options contains the configuration options for tuning
// the subdomain enumeration process.
type Options struct {
	Verbose        bool // Verbose flag indicates whether to show verbose output or not
	NoColor        bool // No-Color disables the colored output
	JSON           bool // JSON specifies whether to use json for output format or text file
	HostIP         bool // HostIP specifies whether to write subdomains in host:ip format
	Silent         bool // Silent suppresses any extra text and only writes subdomains to screen
	ListSources    bool // ListSources specifies whether to list all available sources
	RemoveWildcard bool // RemoveWildcard specifies whether to remove potential wildcard or dead subdomains from the results.
	CaptureSources bool // CaptureSources specifies whether to save all sources that returned a specific domains or just the first source
	Stdin          bool // Stdin specifies whether stdin input was given to the process
	Version        bool // Version specifies if we should just show version and exit
	OnlyRecursive  bool // Recursive specifies whether to use only recursive subdomain enumeration sources
	// Recrusive contains the list of recursive subdomain enum sources
	Recursive goflags.NormalizedStringSlice `yaml:"recursive,omitempty"`
	All       bool                          // All specifies whether to use all (slow) sources.
	// AllSources contains the list of all sources for enumeration (slow)
	AllSources         goflags.NormalizedStringSlice `yaml:"all-sources,omitempty"`
	Threads            int                           // Thread controls the number of threads to use for active enumerations
	Timeout            int                           // Timeout is the seconds to wait for sources to respond
	MaxEnumerationTime int                           // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
	Domain             goflags.NormalizedStringSlice // Domain is the domain to find subdomains for
	DomainsFile        string                        // DomainsFile is the file containing list of domains to find subdomains for
	Output             io.Writer
	OutputFile         string // Output is the file to write found subdomains to.
	OutputDirectory    string // OutputDirectory is the directory to write results to in case list of domains is given
	// Sources contains a comma-separated list of sources to use for enumeration
	Sources goflags.NormalizedStringSlice `yaml:"sources,omitempty"`
	// ExcludeSources contains the comma-separated sources to not include in the enumeration process
	ExcludeSources goflags.NormalizedStringSlice `yaml:"exclude-sources,omitempty"`
	// Resolvers is the comma-separated resolvers to use for enumeration
	Resolvers      goflags.NormalizedStringSlice `yaml:"resolvers,omitempty"`
	ResolverList   string                        // ResolverList is a text file containing list of resolvers to use for enumeration
	Config         string                        // Config contains the location of the config file
	ProviderConfig string                        // ProviderConfig contains the location of the provider config file
	Proxy          string                        // HTTP proxy
	RateLimit      int                           // Maximum number of HTTP requests to send per second
	// YAMLConfig contains the unmarshalled yaml config file
	Providers  *Providers
	ExcludeIps bool
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	// Seed default random number generator
	rand.Seed(time.Now().UnixNano())

	// Migrate config to provider config
	if fileutil.FileExists(defaultConfigLocation) && !fileutil.FileExists(defaultProviderConfigLocation) {
		gologger.Info().Msgf("Detected old %s config file, trying to migrate providers to %s\n", defaultConfigLocation, defaultProviderConfigLocation)
		if err := migrateToProviderConfig(defaultConfigLocation, defaultProviderConfigLocation); err != nil {
			gologger.Warning().Msgf("Could not migrate providers from existing config (%s) to provider config (%s): %s\n", defaultConfigLocation, defaultProviderConfigLocation, err)
		} else {
			//cleanup the existing config file post migration
			os.Remove(defaultConfigLocation)
			gologger.Info().Msgf("Migrated %s to %s successfully\n", defaultConfigLocation, defaultProviderConfigLocation)
		}
	}

	options := &Options{}

	var err error
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Subfinder is a subdomain discovery tool that discovers subdomains for websites by using passive online sources.`)

	createGroup(flagSet, "input", "Input",
		flagSet.NormalizedStringSliceVarP(&options.Domain, "domain", "d", []string{}, "domains to find subdomains for"),
		flagSet.StringVarP(&options.DomainsFile, "list", "dL", "", "file containing list of domains for subdomain discovery"),
	)

	createGroup(flagSet, "source", "Source",
		flagSet.NormalizedStringSliceVarP(&options.Sources, "sources", "s", []string{}, "specific sources to use for discovery (-s crtsh,github)"),
		flagSet.BoolVar(&options.OnlyRecursive, "recursive", false, "use only recursive sources"),
		flagSet.BoolVar(&options.All, "all", false, "use all sources for enumeration (slow)"),
		flagSet.NormalizedStringSliceVarP(&options.ExcludeSources, "exclude-sources", "es", []string{}, "sources to exclude from enumeration (-es archiveis,zoomeye)"),
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
		flagSet.NormalizedStringSliceVar(&options.Resolvers, "r", []string{}, "comma separated list of resolvers to use"),
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
	options.Stdin = hasStdin()

	// Read the inputs and configure the logging
	options.configureOutput()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Check if the application loading with any provider configuration, then take it
	// Otherwise load the default provider config
	if fileutil.FileExists(options.ProviderConfig) {
		gologger.Info().Msgf("Loading provider config file %s", options.ProviderConfig)
		options.loadProvidersFrom(options.ProviderConfig)
	} else {
		gologger.Info().Msg("Loading the default")
		options.loadProvidersFrom(defaultProviderConfigLocation)
	}
	if options.ListSources {
		listSources(options)
		os.Exit(0)
	}

	options.preProcessOptions()

	if !options.Silent {
		showBanner()
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err = options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

func migrateToProviderConfig(source, dest string) error {
	fileSource, err := os.Open(source)
	if err != nil {
		return err
	}
	defer fileSource.Close()

	providers := &Providers{}

	// create empty template at destination, so in case of failure, the file is generated
	if err := providers.MarshalTo(dest); err != nil {
		return err
	}

	// unmarshal fields to migrate into temporary struct
	if err := yaml.NewDecoder(fileSource).Decode(providers); isFatalErr(err) {
		return err
	}

	// re-marshal to destination
	return providers.MarshalTo(dest)
}

func isFatalErr(err error) bool {
	return err != nil && !errors.Is(err, io.EOF)
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
	gologger.Info().Msgf("Current list of available sources. [%d]\n", len(options.AllSources))
	gologger.Info().Msgf("Sources marked with an * needs key or token in order to work.\n")
	gologger.Info().Msgf("You can modify %s to configure your keys / tokens.\n\n", options.ProviderConfig)

	keys := options.Providers.GetKeys()
	needsKey := make(map[string]interface{})
	keysElem := reflect.ValueOf(&keys).Elem()
	for i := 0; i < keysElem.NumField(); i++ {
		needsKey[strings.ToLower(keysElem.Type().Field(i).Name)] = keysElem.Field(i).Interface()
	}

	for _, source := range options.AllSources {
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
