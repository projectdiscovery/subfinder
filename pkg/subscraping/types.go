package subscraping

import (
	"context"
	"net/http"
	"regexp"
)

// Source is an interface inherited by each passive source
type Source interface {
	// Run takes a domain as argument and a session object
	// which contains the extractor for subdomains, http client
	// and other stuff.
	Run(context.Context, string, *Session) <-chan Result
	// Name returns the name of the source
	Name() string
}

// Session is the option passed to the source, an option is created
// uniquely for eac source.
type Session struct {
	// Extractor is the regex for subdomains created for each domain
	Extractor *regexp.Regexp
	// Keys is the API keys for the application
	Keys Keys
	// Client is the current http client
	Client *http.Client
}

// Keys contains the current API Keys we have in store
type Keys struct {
	Binaryedge           string `json:"binaryedge"`
	CensysToken          string `json:"censysUsername"`
	CensysSecret         string `json:"censysPassword"`
	Certspotter          string `json:"certspotter"`
	PassiveTotalUsername string `json:"passivetotal_username"`
	PassiveTotalPassword string `json:"passivetotal_password"`
	Securitytrails       string `json:"securitytrails"`
	Shodan               string `json:"shodan"`
	URLScan              string `json:"urlscan"`
	Virustotal           string `json:"virustotal"`
}

// Result is a result structure returned by a source
type Result struct {
	Type   ResultType
	Source string
	Value  string
	Error  error
}

// ResultType is the type of result returned by the source
type ResultType int

// Types of results returned by the source
const (
	Subdomain ResultType = iota
	Error
)
