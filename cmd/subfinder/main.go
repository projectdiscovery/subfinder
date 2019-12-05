package main

import (
	"github.com/projectdiscovery/subfinder/pkg/log"
	"github.com/projectdiscovery/subfinder/pkg/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	runner, err := runner.NewRunner(options)
	if err != nil {
		log.Fatalf("Could not create runner: %s\n", err)
	}

	err = runner.RunEnumeration()
	if err != nil {
		log.Fatalf("Could not run enumeration: %s\n", err)
	}
}
