package runner

import (
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/subfinder/subfinder/pkg/subscraping"
	"gopkg.in/yaml.v3"
)

// ConfigFile contains the fields stored in the configuration file
type ConfigFile struct {
	// Resolvers contains the list of resolvers to use while resolving
	Resolvers []string `yaml:"resolvers,omitempty"`
	// Sources contains a list of sources to use for enumeration
	Sources []string `yaml:"sources,omitempty"`
	// ExcludeSources contains the sources to not include in the enumeration process
	ExcludeSources []string `yaml:"exclude-sources,omitempty"`
	// API keys for different sources
	Binaryedge     []string `yaml:"binaryedge"`
	Certspotter    []string `yaml:"certspotter"`
	Facebook       []string `yaml:"facebook"`
	PassiveTotal   []string `yaml:"passivetotal"`
	SecurityTrails []string `yaml:"securitytrails"`
	URLScan        []string `yaml:"urlscan"`
	Virustotal     []string `yaml:"virustotal"`
}

// GetConfigDirectory gets the subfinder config directory for a user
func GetConfigDirectory() (string, error) {
	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	var config string

	directory, err := os.UserHomeDir()
	if err != nil {
		return config, err
	}
	config = directory + "/.config/subfinder"
	// Create All directory for subfinder even if they exist
	os.MkdirAll(config, os.ModePerm)

	return config, nil
}

// CheckConfigExists checks if the config file exists in the given path
func CheckConfigExists(configPath string) bool {
	if _, err := os.Stat(configPath); err == nil {
		return true
	} else if os.IsNotExist(err) {
		return false
	}
	return false
}

// MarshalWrite writes the marshalled yaml config to disk
func (c ConfigFile) MarshalWrite(file string) error {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return err
	}

	// Indent the spaces too
	enc := yaml.NewEncoder(f)
	enc.SetIndent(4)
	err = enc.Encode(&c)
	f.Close()
	return err
}

// UnmarshalRead reads the unmarshalled config yaml file from disk
func (c ConfigFile) UnmarshalRead(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	err = yaml.NewDecoder(f).Decode(&c)
	f.Close()
	return err
}

// GetKeys gets the API keys from config file and creates a Keys struct
// We use random selection of api keys from the list of keys supplied.
// Keys that require 2 options are separated by colon (:).
func (c ConfigFile) GetKeys() subscraping.Keys {
	keys := subscraping.Keys{}

	keys.Binaryedge = c.Binaryedge[rand.Intn(len(c.Binaryedge))]
	keys.Certspotter = c.Certspotter[rand.Intn(len(c.Certspotter))]

	facebookKeys := c.Facebook[rand.Intn(len(c.Facebook))]
	parts := strings.Split(facebookKeys, ":")
	if len(parts) == 2 {
		keys.FacebookAppID = parts[0]
		keys.FacebookAppSecret = parts[1]
	}

	passiveTotalKeys := c.PassiveTotal[rand.Intn(len(c.PassiveTotal))]
	parts = strings.Split(passiveTotalKeys, ":")
	if len(parts) == 2 {
		keys.PassiveTotalUsername = parts[0]
		keys.PassiveTotalPassword = parts[1]
	}

	keys.Securitytrails = c.SecurityTrails[rand.Intn(len(c.SecurityTrails))]
	keys.URLScan = c.URLScan[rand.Intn(len(c.URLScan))]
	keys.Virustotal = c.Virustotal[rand.Intn(len(c.Virustotal))]
	return keys
}
