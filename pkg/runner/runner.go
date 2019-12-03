package runner

// Runner is an instance of the subdomain enumeration
// client used to orchestrate the whole process.
type Runner struct {
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options Options) *Runner {

	return &Runner{}
}
