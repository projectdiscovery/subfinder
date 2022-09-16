package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/projectdiscovery/subfinder/v2/pkg/testutils"
)

type dnsrepoTestcases struct{}

func (h dnsrepoTestcases) Execute() error {
	token := os.Getenv("DNSREPO_API_KEY")
	if token == "" {
		return errors.New("missing dns repo api key")
	}
	dnsToken := fmt.Sprintf(`dnsrepo: [%s]`, token)
	file, err := os.CreateTemp("", "provider.yaml")
	if err != nil {
		return err
	}
	defer os.RemoveAll(file.Name())
	_, err = file.WriteString(dnsToken)
	if err != nil {
		return err
	}
	results, err := testutils.RunSubfinderAndGetResults(debug, "hackerone.com", "-s", "dnsrepo", "-provider-config", file.Name())
	if err != nil {
		return err
	}
	return expectResultsGreaterThanCount(results, 0)
}
