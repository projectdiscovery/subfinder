package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	contextutil "github.com/projectdiscovery/utils/context"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Runner is an instance of the subdomain enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options           *Options
	passiveAgent      *passive.Agent
	resolverClient    *resolve.Resolver
	rateLimit         *subscraping.CustomRateLimit
	newPassiveAgent   func() *passive.Agent
	sharedRateLimiter subscraping.RequestLimiter
	outputMu          *sync.Mutex
	domainOutput      bool
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	options.ConfigureOutput()
	runner := &Runner{options: options}

	var providerKeys map[string][]string

	// Check if the application loading with any provider configuration, then take it
	// Otherwise load the default provider config
	if fileutil.FileExists(options.ProviderConfig) {
		gologger.Info().Msgf("Loading provider config from %s", options.ProviderConfig)
		providerKeys = options.loadProvidersFrom(options.ProviderConfig)
	} else {
		gologger.Info().Msgf("Loading provider config from the default location: %s", defaultProviderConfigLocation)
		providerKeys = options.loadProvidersFrom(defaultProviderConfigLocation)
	}

	// Initialize the passive subdomain enumeration engine
	runner.initializePassiveEngine(providerKeys)

	// Initialize the subdomain resolver
	err := runner.initializeResolver()
	if err != nil {
		return nil, err
	}

	// Initialize the custom rate limit
	runner.rateLimit = &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, uint]{
			Map: make(map[string]uint),
		},
		CustomDuration: mapsutil.SyncLockMap[string, time.Duration]{
			Map: make(map[string]time.Duration),
		},
	}

	for source, sourceRateLimit := range options.RateLimits.AsMap() {
		if sourceRateLimit.MaxCount > 0 && sourceRateLimit.MaxCount <= math.MaxUint {
			_ = runner.rateLimit.Custom.Set(source, sourceRateLimit.MaxCount)
			if sourceRateLimit.Duration > 0 {
				_ = runner.rateLimit.CustomDuration.Set(source, sourceRateLimit.Duration)
			}
		}
	}

	return runner, nil
}

// RunEnumeration wraps RunEnumerationWithCtx with an empty context
func (r *Runner) RunEnumeration() error {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.RunEnumerationWithCtx(ctx)
}

// RunEnumerationWithCtx runs the subdomain enumeration flow on the targets specified
func (r *Runner) RunEnumerationWithCtx(ctx context.Context) error {
	outputs := []io.Writer{r.options.Output}

	if len(r.options.Domain) > 0 {
		domainsReader := strings.NewReader(strings.Join(r.options.Domain, "\n"))
		return r.EnumerateMultipleDomainsWithCtx(ctx, domainsReader, outputs)
	}

	// If we have multiple domains as input,
	if r.options.DomainsFile != "" {
		f, err := os.Open(r.options.DomainsFile)
		if err != nil {
			return err
		}
		err = r.EnumerateMultipleDomainsWithCtx(ctx, f, outputs)
		if closeErr := f.Close(); closeErr != nil {
			gologger.Error().Msgf("Error closing file %s: %s", r.options.DomainsFile, closeErr)
		}
		return err
	}

	// If we have STDIN input, treat it as multiple domains
	if r.options.Stdin {
		return r.EnumerateMultipleDomainsWithCtx(ctx, os.Stdin, outputs)
	}
	return nil
}

// EnumerateMultipleDomains wraps EnumerateMultipleDomainsWithCtx with an empty context
func (r *Runner) EnumerateMultipleDomains(reader io.Reader, writers []io.Writer) error {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.EnumerateMultipleDomainsWithCtx(ctx, reader, writers)
}

// EnumerateMultipleDomainsWithCtx enumerates at most Threads domains concurrently.
// Completed domains are written together; domain output order is unspecified.
func (r *Runner) EnumerateMultipleDomainsWithCtx(ctx context.Context, reader io.Reader, writers []io.Writer) (err error) {
	if r.options.Threads < 0 {
		return fmt.Errorf("threads must be positive")
	}
	// SDK callers historically could leave Threads unset for passive enumeration.

	workers := max(1, r.options.Threads)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	limiter, err := r.passiveAgent.NewRateLimiter(ctx, r.options.RateLimit, r.rateLimit)
	if err != nil {
		return fmt.Errorf("create batch rate limiter: %w", err)
	}
	defer limiter.Close()

	batch := *r
	options := *r.options
	batch.options = &options
	batch.sharedRateLimiter = limiter
	batch.outputMu = &sync.Mutex{}
	batch.domainOutput = true

	if options.RemoveWildcard {
		batch.resolverClient = r.resolverClient.WithConcurrencyLimit(workers)
	}

	if callback := options.ResultCallback; callback != nil {
		options.ResultCallback = func(entry *resolve.HostEntry) {
			batch.outputMu.Lock()
			defer batch.outputMu.Unlock()
			callback(entry)
		}
	}

	var sharedFile *os.File
	defer func() {
		if sharedFile != nil {
			err = errors.Join(err, sharedFile.Close())
		}
	}()

	jobs := make(chan string)

	var wg sync.WaitGroup
	var firstError error
	var errorOnce sync.Once

	fail := func(err error) {
		errorOnce.Do(func() { firstError = err; cancel() })
	}

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				if ctx.Err() != nil {
					return
				}

				worker := batch
				worker.passiveAgent = r.newPassiveAgent()

				if _, err := worker.EnumerateSingleDomainWithCtx(ctx, domain, writers); err != nil {
					fail(err)
					return
				}
			}
		}()
	}

	scanner := bufio.NewScanner(reader)
	ip := regexp.MustCompile(`^([0-9\.]+$)`)

scan:
	for ctx.Err() == nil && scanner.Scan() {
		domain := replacer.Replace(preprocessDomain(scanner.Text()))
		if domain == "" || (options.ExcludeIps && ip.MatchString(domain)) {
			continue
		}

		// Validate destinations before spending provider requests. Open the shared
		// output only after the first accepted domain so empty input has no effects.
		if options.OutputFile != "" && sharedFile == nil {
			sharedFile, err = NewOutputWriter(options.JSON).createFile(options.OutputFile, true)
			if err != nil {
				fail(err)
				break
			}

			writers = append(append([]io.Writer(nil), writers...), sharedFile)
			batch.domainOutput = false
		} else if options.OutputFile == "" && options.OutputDirectory != "" {
			suffix := ".txt"
			if options.JSON {
				suffix = ".json"
			}

			batch.outputMu.Lock()

			file, openErr := NewOutputWriter(options.JSON).createFile(path.Join(options.OutputDirectory, domain+suffix), true)
			if openErr == nil {
				openErr = file.Close()
			}

			batch.outputMu.Unlock()

			if openErr != nil {
				fail(openErr)
				break
			}
		}

		select {
		case <-ctx.Done():
			break scan
		case jobs <- domain:
		}
	}

	if err := scanner.Err(); err != nil {
		fail(fmt.Errorf("read domains: %w", err))
	}

	close(jobs)
	wg.Wait()

	if firstError != nil {
		return firstError
	}

	return ctx.Err()
}
