package subf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/engines/passive"
	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// Subfinder represent a subdomain enumerator instance
type Subfinder struct {
	State *helper.State
}

// NewSubfinder instantiate a new subfinder
func NewSubfinder() *Subfinder {
	return &Subfinder{
		State: helper.InitState(),
	}
}

// Init setup the instance
func (s *Subfinder) Init() {
	s.parseConfig()
	s.parseSetting()
	s.parseComResolver()
	s.parseListResolver()
	s.setCommonResolver()
	s.setOutput()
	s.setDomain()
}

func (s *Subfinder) parseConfig() {
	if s.State.SetConfig == "none" {
		return
	}

	setConfig := strings.Split(s.State.SetConfig, ",")

	// Build Configuration path
	home := helper.GetHomeDir()
	path := home + "/.config/subfinder/config.json"

	for _, config := range setConfig {
		object := strings.Split(config, "=")

		// Change value dynamically using reflect package
		if strings.EqualFold(object[0], "virustotalapikey") {
			reflect.ValueOf(&s.State.ConfigState).Elem().FieldByName("VirustotalAPIKey").SetString(object[1])
		} else if strings.EqualFold(object[0], "passivetotalusername") {
			reflect.ValueOf(&s.State.ConfigState).Elem().FieldByName("PassivetotalUsername").SetString(object[1])
		} else if strings.EqualFold(object[0], "passivetotalkey") {
			reflect.ValueOf(&s.State.ConfigState).Elem().FieldByName("PassivetotalKey").SetString(object[1])
		} else if strings.EqualFold(object[0], "securitytrailskey") {
			reflect.ValueOf(&s.State.ConfigState).Elem().FieldByName("SecurityTrailsKey").SetString(object[1])
		} else if strings.EqualFold(object[0], "riddleremail") {
			reflect.ValueOf(&s.State.ConfigState).Elem().FieldByName("RiddlerEmail").SetString(object[1])
		} else if strings.EqualFold(object[0], "riddlerpassword") {
			reflect.ValueOf(&s.State.ConfigState).Elem().FieldByName("RiddlerPassword").SetString(object[1])
		} else if strings.EqualFold(object[0], "censysusername") {
			reflect.ValueOf(&s.State.ConfigState).Elem().FieldByName("CensysUsername").SetString(object[1])
		} else if strings.EqualFold(object[0], "censyssecret") {
			reflect.ValueOf(&s.State.ConfigState).Elem().FieldByName("CensysSecret").SetString(object[1])
		} else if strings.EqualFold(object[0], "shodankey") {
			reflect.ValueOf(&s.State.ConfigState).Elem().FieldByName("ShodanAPIKey").SetString(object[1])
		}

		configJSON, _ := json.MarshalIndent(s.State.ConfigState, "", "	")
		err := ioutil.WriteFile(path, configJSON, 0644)
		if err != nil {
			fmt.Printf("\n\n[!] Error : %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully configured %s%s%s=>%s\n", helper.Info, object[0], helper.Reset, object[1])
	}
}

func (s *Subfinder) parseSetting() {
	if s.State.SetSetting == "none" {
		return
	}

	setSetting := strings.Split(s.State.SetSetting, ",")

	for _, setting := range setSetting {
		object := strings.Split(setting, "=")

		// Change value dynamically using reflect package
		reflect.ValueOf(&s.State.CurrentSettings).Elem().FieldByName(object[0]).SetString(object[1])
		if !s.State.Silent && s.State.Verbose {
			fmt.Printf("Successfully Set %s%s%s=>%s\n", helper.Info, object[0], helper.Reset, object[1])
		}
	}
}

func (s *Subfinder) parseComResolver() {
	if s.State.ComResolver == "" {
		return
	}

	setResolvers := strings.Split(s.State.ComResolver, ",")

	s.State.LoadResolver = append(s.State.LoadResolver, setResolvers...)
}

func (s *Subfinder) parseListResolver() {
	if s.State.ListResolver == "" {
		return
	}

	// Load the resolvers from file
	file, err := os.Open(s.State.ListResolver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		os.Exit(1)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		s.State.LoadResolver = append(s.State.LoadResolver, scanner.Text())
	}
}

func (s *Subfinder) setCommonResolver() {
	// Use the default resolvers
	if s.State.ComResolver != "" && s.State.ListResolver != "" {
		return
	}

	s.State.LoadResolver = append(s.State.LoadResolver, "1.1.1.1")
	s.State.LoadResolver = append(s.State.LoadResolver, "8.8.8.8")
	s.State.LoadResolver = append(s.State.LoadResolver, "8.8.4.4")
}

func (s *Subfinder) setOutput() {
	if s.State.Output != "" {
		dir := filepath.Dir(s.State.Output)
		if !helper.Exists(dir) {
			fmt.Printf("\n%s-> The specified output directory does not exists !%s\n", helper.Yellow, helper.Reset)
		} else {
			// Get a handle to the out file if it is not json
			if !s.State.AquatoneJSON && !s.State.IsJSON {
				var err error
				s.State.OutputHandle, err = os.OpenFile(s.State.Output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
				if err != nil {
					return
				}
			}
		}
	} else if s.State.OutputDir != "" {
		if !helper.Exists(s.State.OutputDir) {
			fmt.Printf("\n%s-> The specified output directory does not exists !%s\n", helper.Yellow, helper.Reset)
		}
	}
}

func (s *Subfinder) setDomain() {
	if s.State.Domain == "" && s.State.DomainList == "" {
		if !s.State.Silent {
			fmt.Printf("%s-> Missing \"domain\" argument %s\nTry %s'./subfinder -h'%s for more information\n", helper.Bad, helper.Reset, helper.Info, helper.Reset)
		}
		os.Exit(1)
	}
}

// PassiveEnumeration execute a passive enumeration
func (s *Subfinder) PassiveEnumeration() []string {
	return passive.Enumerate(s.State)
}
