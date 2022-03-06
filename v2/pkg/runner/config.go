package runner

import (
	"math/rand"
	"os"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"gopkg.in/yaml.v3"
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
		keys.Binaryedge = c.Binaryedge[rand.Intn(len(c.Binaryedge))]
	}
	if len(c.C99) > 0 {
		keys.C99 = c.C99[rand.Intn(len(c.C99))]
	}

	if len(c.Bufferover) > 0 {
		keys.Bufferover = c.Bufferover[rand.Intn(len(c.Bufferover))]
	}

	if len(c.Censys) > 0 {
		censysKeys := c.Censys[rand.Intn(len(c.Censys))]
		parts := strings.Split(censysKeys, ":")
		if len(parts) == MultipleKeyPartsLength {
			keys.CensysToken = parts[0]
			keys.CensysSecret = parts[1]
		}
	}

	if len(c.Certspotter) > 0 {
		keys.Certspotter = c.Certspotter[rand.Intn(len(c.Certspotter))]
	}
	if len(c.Chaos) > 0 {
		keys.Chaos = c.Chaos[rand.Intn(len(c.Chaos))]
	}
	if len(c.Chinaz) > 0 {
		keys.Chinaz = c.Chinaz[rand.Intn(len(c.Chinaz))]
	}
	if (len(c.DNSDB)) > 0 {
		keys.DNSDB = c.DNSDB[rand.Intn(len(c.DNSDB))]
	}
	if (len(c.GitHub)) > 0 {
		keys.GitHub = c.GitHub
	}

	if len(c.IntelX) > 0 {
		intelxKeys := c.IntelX[rand.Intn(len(c.IntelX))]
		parts := strings.Split(intelxKeys, ":")
		if len(parts) == MultipleKeyPartsLength {
			keys.IntelXHost = parts[0]
			keys.IntelXKey = parts[1]
		}
	}

	if len(c.PassiveTotal) > 0 {
		passiveTotalKeys := c.PassiveTotal[rand.Intn(len(c.PassiveTotal))]
		parts := strings.Split(passiveTotalKeys, ":")
		if len(parts) == MultipleKeyPartsLength {
			keys.PassiveTotalUsername = parts[0]
			keys.PassiveTotalPassword = parts[1]
		}
	}

	if len(c.Robtex) > 0 {
		keys.Robtex = c.Robtex[rand.Intn(len(c.Robtex))]
	}

	if len(c.SecurityTrails) > 0 {
		keys.Securitytrails = c.SecurityTrails[rand.Intn(len(c.SecurityTrails))]
	}
	if len(c.Shodan) > 0 {
		keys.Shodan = c.Shodan[rand.Intn(len(c.Shodan))]
	}
	if len(c.Spyse) > 0 {
		keys.Spyse = c.Spyse[rand.Intn(len(c.Spyse))]
	}
	if len(c.ThreatBook) > 0 {
		keys.ThreatBook = c.ThreatBook[rand.Intn(len(c.ThreatBook))]
	}
	if len(c.URLScan) > 0 {
		keys.URLScan = c.URLScan[rand.Intn(len(c.URLScan))]
	}
	if len(c.Virustotal) > 0 {
		keys.Virustotal = c.Virustotal[rand.Intn(len(c.Virustotal))]
	}
	if len(c.ZoomEye) > 0 {
		zoomEyeKeys := c.ZoomEye[rand.Intn(len(c.ZoomEye))]
		parts := strings.Split(zoomEyeKeys, ":")
		if len(parts) == MultipleKeyPartsLength {
			keys.ZoomEyeUsername = parts[0]
			keys.ZoomEyePassword = parts[1]
		}
	}
	if len(c.ZoomEyeApi) > 0 {
		keys.ZoomEyeKey = c.ZoomEyeApi[rand.Intn(len(c.ZoomEyeApi))]
	}
	if len(c.Fofa) > 0 {
		fofaKeys := c.Fofa[rand.Intn(len(c.Fofa))]
		parts := strings.Split(fofaKeys, ":")
		if len(parts) == MultipleKeyPartsLength {
			keys.FofaUsername = parts[0]
			keys.FofaSecret = parts[1]
		}
	}
	if len(c.FullHunt) > 0 {
		keys.FullHunt = c.FullHunt[rand.Intn(len(c.FullHunt))]
	}
	return keys
}
