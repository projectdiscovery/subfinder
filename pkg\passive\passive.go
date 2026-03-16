package passive

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Agent is a struct for running passive subdomain enumeration
type Agent struct {
	sources          map[string]subscraping.Source
}

// New creates a new passive results enum agent
func New(sourceNames, excludedSourceNames []string, all bool) *Agent {
	agent := &Agent{}
	agent.sources = make(map[string]subscraping.Source)
	
	// populate sources based on names/all
	// ...
	
	return agent
}
