# SubFinder Documentation

:+1::tada: First off, Many Thanks for taking the time to contribute! :tada::+1:

The follwing is a document describing the project structure of SubFinder subdomain enumeration tool and teaching you how to contribute to it.

### Project Structure

SubFinder is written in golang. The author has tried to keep the code as simple and modular as possible. There can be flaws in the golang implementation or there may be many things which can be done better. Please create an issue with the details and we would be more than happy to implement your suggestions. Pull Requests are more appreciated :+1:.

Comments can be found throughout the majority of the code base explaining functionality of usage. The codebase is pretty simple and modular and you can easily understand the structure and contribute to the codebase.

### Adding new Passive Sources

Passive Sources are data sources which can be used to find subdomains without directly connecting to the site. It can easily fetch many subdomains which cannot be found through plain bruteforcing and alterations. SubFinder uses multiple passive sources which are organized in `github.com/ice3man543/subfinder/libsubfinder/sources`. Each passive source has it's own directory which contains a subpackage under the package sources. Each passive source must export a query function. This allows the code to retain a similar structure throughout the tool. 

- Create a directory `github.com/ice3man543/subfinder/libsubfinder/sources/example`
- Create a file called example.go in `example` directory.

Here is a boilerplate code for a passive package called example.

```golang
package example 	// The first line contains package name, like example

import (
	"github.com/ice3man543/subfinder/libsubfinder/helper" 	// Obligatory, Contains helper class 
)

// Contains all subdomains found
var subdomains []string

// 
// Query : Each passive package exports a Query function 
//  which returns all results found.
// 
// @param state : Current application state
// @param ch : Channel for our result structure
func Query(state *helper.State, ch chan helper.Result) {
	// Perform all the operations here
	...

	// In case of error handling, return error
	if err != nil {
		result.Error = err
		ch <- result
		return
	}

	for _, found := range block.Dns_names {
			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sEXAMPLE%s] %s", helper.Red, helper.Reset, found)
				} else {
					fmt.Printf("\n[EXAMPLE] %s", found)
				}
			}
			subdomains = append(subdomains, found)
		}	
	}

	// Return success result
	result.Subdomains = subdomains
	result.Error = nil
	ch <-result
}

```

Some notes :
1. A Package can have as many functions as you want. But all functionality must be exported by the Query function itself.
2. The helper class exports a function `helper.GetHTTPResponse("https://example.com?domain="+state.Domain, state.Timeout)` which can help with HTTP requests.
3. We have been keeping Package count almost to none. Please use `Regexp` package or native Golang HTML parser.

After you have created your package, it's time to import it. All logic for passive sources is in `github.com/ice3man543/subfinder/libsubfinder/engines/passive/passive.go`.

- Import your custom package in passive.go.
```golang
package passive 

import (
	...

	// Load different Passive data sources
	...

	"github.com/ice3man543/subfinder/libsubfinder/sources/example"
)
```

- Add your data source to Source struct at the last of all sources before NoOfSources.

```golang
type Source struct {
	...
	Example 		bool 		// Your example data source

	NoOfSources		int
}

func PassiveDiscovery(state *helper.State) (finalPassiveSubdomains []string) {
```

- Add a false statement to your sourceConfig object at the last before NoOfSources.

```golang
func PassiveDiscovery(state *helper.State) (finalPassiveSubdomains []string) {
	sourceConfig := Source{... false, 0}
```

- Add a print statement to all data sources if-block. Also add a true statement to sourceConfig assignment and also increment NoOfSources field by 1.
```golang
if state.Sources == "all" {
		// Search all data sources

		...
		fmt.Printf("\n[-] Searching For Subdomains in Example")
		...

		sourceConfig = Source{... true, 13}
```

- Add an else-if block to the custom source config block.
```golang
else {
		// Check data sources and create a source configuration structure

		dataSources := strings.Split(state.Sources, ",")
		for _, source := range dataSources {
			if source == "crtsh" {
				fmt.Printf("\n[-] Searching For Subdomains in Crt.sh")
				sourceConfig.Crtsh = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1

			...

			} else if source == "example" {
				fmt.Printf("\n[-] Searching For Subdomains in Example")
				sourceConfig.Example = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			}
		}
```

- Add an if-block for main goroutine execution.
```golang
if sourceConfig.Virustotal == true { go virustotal.Query(state, ch) }
if sourceConfig.Example == true { go example.Query(state, ch) }
```

And finally, you have created your own custom passive source.

### Notes

This document is currently in development like this project. If there are any mistakes or questions, feel free to create an issue or contact me directly on twitter or email. Have fun developing it. If you do create something awesome, do share it and we will add your name to the Acknowledgements section. 

---

Written by : @Ice3man