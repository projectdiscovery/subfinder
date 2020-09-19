package main

import (
	"context"

	"github.com/projectdiscovery/fdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/pkg/runner"
)

func main() {
	// Increase the OS file descriptors
	err := fdmax.Set(fdmax.UnixMax)
	if err != nil {
		gologger.Fatalf("Could not set the max file descriptors for the current process: %s\n", err)
	}

	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	newRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatalf("Could not create runner: %s\n", err)
	}

	err = newRunner.RunEnumeration(context.Background())
	if err != nil {
		gologger.Fatalf("Could not run enumeration: %s\n", err)
	}
}
