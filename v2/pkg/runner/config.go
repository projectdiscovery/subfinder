package runner

import (
	"os"

	"gopkg.in/yaml.v3"

	"github.com/projectdiscovery/sliceutil"
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
		keys.Binaryedge = sliceutil.PickRandom(c.Binaryedge)
	}
	if len(c.C99) > 0 {
		keys.C99 = sliceutil.PickRandom(c.C99)
	}

	if len(c.Bufferover) > 0 {
		keys.Bufferover = sliceutil.PickRandom(c.Bufferover)
	}

	if len(c.Censys) > 0 {
		censysKeys := sliceutil.PickRandom(c.Censys)
		if keyPartA, keyPartB, ok := multipartKey(censysKeys); ok {
			keys.CensysToken = keyPartA
			keys.CensysSecret = keyPartB
		}
	}

	if len(c.Certspotter) > 0 {
		keys.Certspotter = sliceutil.PickRandom(c.Certspotter)
	}
	if len(c.Chaos) > 0 {
		keys.Chaos = sliceutil.PickRandom(c.Chaos)
	}
	if len(c.Chinaz) > 0 {
		keys.Chinaz = sliceutil.PickRandom(c.Chinaz)
	}
	if (len(c.DNSDB)) > 0 {
		keys.DNSDB = sliceutil.PickRandom(c.DNSDB)
	}
	if (len(c.GitHub)) > 0 {
		keys.GitHub = c.GitHub
	}

	if len(c.IntelX) > 0 {
		intelxKeys := sliceutil.PickRandom(c.IntelX)
		if keyPartA, keyPartB, ok := multipartKey(intelxKeys); ok {
			keys.IntelXHost = keyPartA
			keys.IntelXKey = keyPartB
		}
	}

	if len(c.PassiveTotal) > 0 {
		passiveTotalKeys := sliceutil.PickRandom(c.PassiveTotal)
		if keyPartA, keyPartB, ok := multipartKey(passiveTotalKeys); ok {
			keys.PassiveTotalUsername = keyPartA
			keys.PassiveTotalPassword = keyPartB
		}
	}

	if len(c.Robtex) > 0 {
		keys.Robtex = sliceutil.PickRandom(c.Robtex)
	}

	if len(c.SecurityTrails) > 0 {
		keys.Securitytrails = sliceutil.PickRandom(c.SecurityTrails)
	}
	if len(c.Shodan) > 0 {
		keys.Shodan = sliceutil.PickRandom(c.Shodan)
	}
	if len(c.ThreatBook) > 0 {
		keys.ThreatBook = sliceutil.PickRandom(c.ThreatBook)
	}
	if len(c.URLScan) > 0 {
		keys.URLScan = sliceutil.PickRandom(c.URLScan)
	}
	if len(c.Virustotal) > 0 {
		keys.Virustotal = sliceutil.PickRandom(c.Virustotal)
	}
	if len(c.ZoomEye) > 0 {
		zoomEyeKeys := sliceutil.PickRandom(c.ZoomEye)
		if keyPartA, keyPartB, ok := multipartKey(zoomEyeKeys); ok {
			keys.ZoomEyeUsername = keyPartA
			keys.ZoomEyePassword = keyPartB
		}
	}
	if len(c.ZoomEyeApi) > 0 {
		keys.ZoomEyeKey = sliceutil.PickRandom(c.ZoomEyeApi)
	}
	if len(c.Fofa) > 0 {
		fofaKeys := sliceutil.PickRandom(c.Fofa)
		if keyPartA, keyPartB, ok := multipartKey(fofaKeys); ok {
			keys.FofaUsername = keyPartA
			keys.FofaSecret = keyPartB
		}
	}
	if len(c.FullHunt) > 0 {
		keys.FullHunt = sliceutil.PickRandom(c.FullHunt)
	}
	return keys
}
