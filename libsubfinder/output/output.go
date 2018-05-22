//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Contains different functions for reporting
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// Write output to a normal text file
func WriteOutputText(state *helper.State, subdomains []string) error {
	file, err := os.Create(state.Output)

	if err != nil {
		return err
	}

	for _, subdomain := range subdomains {
		_, err := io.WriteString(file, subdomain+"\n")
		if err != nil {
			return err
		}
	}

	file.Close()

	return nil
}

// Writes subdomains output to a json file
func WriteOutputJSON(state *helper.State, subdomains []string) error {
	_, err := os.Create(state.Output)

	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(subdomains, "", "    ")
	if err != nil {
		return err
	}

	// Write the output to file
	err = ioutil.WriteFile(state.Output, data, 0644)

	return nil
}

// Writes subdomains output to a json file
func WriteOutputAquatoneJSON(state *helper.State, subdomains []helper.Domain) error {
	m := make(map[string]string)
	_, err := os.Create(state.Output)

	if err != nil {
		return err
	}

	for _, subdomain := range subdomains {
		// Set correct values
		m[subdomain.Fqdn] = subdomain.IP
	}

	data, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		return err
	}

	// Write the output to file
	err = ioutil.WriteFile(state.Output, data, 0644)

	return nil
}

func WriteOutputToFile(state *helper.State, subdomains []string) (err error) {
	if state.Output != "" {
		if state.IsJSON == true {
			err := WriteOutputJSON(state, subdomains)
			if err != nil {
				fmt.Printf("\nerror : %v", err)
			} else {
				if state.Silent != true {
					fmt.Printf("\n[~] Successfully Written Output to File : %s\n", state.Output)
				}
			}
		} else {
			err := WriteOutputText(state, subdomains)
			if err != nil {
				fmt.Printf("\nerror : %v", err)
			} else {
				if state.Silent != true {
					fmt.Printf("\n[~] Successfully Written Output to File : %s\n", state.Output)
				}
			}
		}
	}

	return nil
}
func WriteOutputToDir(state *helper.State, subdomains []string, domain string) (err error) {
	if state.OutputDir != "" {
		if state.IsJSON == false {
			file, err := os.Create(state.OutputDir + domain + "_hosts.txt")

			if err != nil {
				return err
			}

			for _, subdomain := range subdomains {
				_, err := io.WriteString(file, subdomain+"\n")
				if err != nil {
					return err
				}
			}

			file.Close()

			return nil
		} else {

			_, err := os.Create(state.OutputDir + domain + "_hosts.json")

			if err != nil {
				return err
			}

			data, err := json.MarshalIndent(subdomains, "", "    ")
			if err != nil {
				return err
			}

			// Write the output to file
			err = ioutil.WriteFile(state.OutputDir+domain+"_hosts.json", data, 0644)

			return nil
		}
	}

	return nil
}
