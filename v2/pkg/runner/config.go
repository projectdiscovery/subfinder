package runner

import (
	"os"

	"gopkg.in/yaml.v3"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// MultipleKeyPartsLength is the max length for multiple keys
const MultipleKeyPartsLength = 2

// Providers contains the providers stored in the configuration file
type Providers struct {
	// API keys for different sources
	Bufferover     []string `yaml:"bufferover"`
	Binaryedge     []string `yaml:"binaryedge"`
	C99            []string `yaml:"c99"`
	Censys         []string `yaml:"censys"`
	Certspotter    []string `yaml:"certspotter"`
	Chaos          []string `yaml:"chaos"`
	Chinaz         []string `yaml:"chinaz"`
	DNSDB          []string `yaml:"dnsdb"`
	GitHub         []string `yaml:"github"`
	IntelX         []string `yaml:"intelx"`
	PassiveTotal   []string `yaml:"passivetotal"`
	Robtex         []string `yaml:"robtex"`
	SecurityTrails []string `yaml:"securitytrails"`
	Shodan         []string `yaml:"shodan"`
	Spyse          []string `yaml:"spyse"`
	ThreatBook     []string `yaml:"threatbook"`
	URLScan        []string `yaml:"urlscan"`
	Virustotal     []string `yaml:"virustotal"`
	ZoomEye        []string `yaml:"zoomeye"`
	ZoomEyeApi     []string `yaml:"zoomeyeapi"`
	Fofa           []string `yaml:"fofa"`
	FullHunt       []string `json:"fullhunt"`
}

// GetConfigDirectory gets the subfinder config directory for a user
func GetConfigDirectory() (string, error) {
	var config string

	directory, err := os.UserHomeDir()
	if err != nil {
		return config, err
	}
	config = directory + "/.config/subfinder"

	// Create All directory for subfinder even if they exist
	err = os.MkdirAll(config, os.ModePerm)
	if err != nil {
		return config, err
	}

	return config, nil
}

// MarshalTo writes the marshaled yaml config to disk
func (c *Providers) MarshalTo(file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	return yaml.NewEncoder(f).Encode(c)
}

// MarshalTo writes the marshaled yaml config to disk
func (c *Providers) UnmarshalFrom(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	return yaml.NewDecoder(f).Decode(c)
}

// GetKeys gets the API keys from config file and creates a Keys struct
// We use random selection of api keys from the list of keys supplied.
// Keys that require 2 options are separated by colon (:).
func (c *Providers) GetKeys() subscraping.Keys {
	keys := subscraping.Keys{}

	if len(c.Binaryedge) > 0 {
		keys.Binaryedge = randomEntry(c.Binaryedge)
	}
	if len(c.C99) > 0 {
		keys.C99 = randomEntry(c.C99)
	}

	if len(c.Bufferover) > 0 {
		keys.Bufferover = randomEntry(c.Bufferover)
	}

	if len(c.Censys) > 0 {
		censysKeys := randomEntry(c.Censys)
		if keyPartA, keyPartB, ok := multipartKey(censysKeys); ok {
			keys.CensysToken = keyPartA
			keys.CensysSecret = keyPartB
		}
	}

	if len(c.Certspotter) > 0 {
		keys.Certspotter = randomEntry(c.Certspotter)
	}
	if len(c.Chaos) > 0 {
		keys.Chaos = randomEntry(c.Chaos)
	}
	if len(c.Chinaz) > 0 {
		keys.Chinaz = randomEntry(c.Chinaz)
	}
	if (len(c.DNSDB)) > 0 {
		keys.DNSDB = randomEntry(c.DNSDB)
	}
	if (len(c.GitHub)) > 0 {
		keys.GitHub = c.GitHub
	}

	if len(c.IntelX) > 0 {
		intelxKeys := randomEntry(c.IntelX)
		if keyPartA, keyPartB, ok := multipartKey(intelxKeys); ok {
			keys.IntelXHost = keyPartA
			keys.IntelXKey = keyPartB
		}
	}

	if len(c.PassiveTotal) > 0 {
		passiveTotalKeys := randomEntry(c.PassiveTotal)
		if keyPartA, keyPartB, ok := multipartKey(passiveTotalKeys); ok {
			keys.PassiveTotalUsername = keyPartA
			keys.PassiveTotalPassword = keyPartB
		}
	}

	if len(c.Robtex) > 0 {
		keys.Robtex = randomEntry(c.Robtex)
	}

	if len(c.SecurityTrails) > 0 {
		keys.Securitytrails = randomEntry(c.SecurityTrails)
	}
	if len(c.Shodan) > 0 {
		keys.Shodan = randomEntry(c.Shodan)
	}
	if len(c.Spyse) > 0 {
		keys.Spyse = randomEntry(c.Spyse)
	}
	if len(c.ThreatBook) > 0 {
		keys.ThreatBook = randomEntry(c.ThreatBook)
	}
	if len(c.URLScan) > 0 {
		keys.URLScan = randomEntry(c.URLScan)
	}
	if len(c.Virustotal) > 0 {
		keys.Virustotal = randomEntry(c.Virustotal)
	}
	if len(c.ZoomEye) > 0 {
		zoomEyeKeys := randomEntry(c.ZoomEye)
		if keyPartA, keyPartB, ok := multipartKey(zoomEyeKeys); ok {
			keys.ZoomEyeUsername = keyPartA
			keys.ZoomEyePassword = keyPartB
		}
	}
	if len(c.ZoomEyeApi) > 0 {
		keys.ZoomEyeKey = randomEntry(c.ZoomEyeApi)
	}
	if len(c.Fofa) > 0 {
		fofaKeys := randomEntry(c.Fofa)
		if keyPartA, keyPartB, ok := multipartKey(fofaKeys); ok {
			keys.FofaUsername = keyPartA
			keys.FofaSecret = keyPartB
		}
	}
	if len(c.FullHunt) > 0 {
		keys.FullHunt = randomEntry(c.FullHunt)
	}
	return keys
}
