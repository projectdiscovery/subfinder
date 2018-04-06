// 
// passive.go : Passive Subdomain Discovery Helper method
//		Calls all the functions and also manages error handling
//
// Written By : @ice3man (Nizamul Rana)
// 
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package passive 

import (
	"fmt"

	"subfinder/libsubfinder/helper"

	// Load different Passive data sources
	"subfinder/libsubfinder/sources/certspotter"
	"subfinder/libsubfinder/sources/crtsh"
	"subfinder/libsubfinder/sources/hackertarget"
	"subfinder/libsubfinder/sources/findsubdomains"
	//"subfinder/libsubfinder/sources/dnsdb"
	"subfinder/libsubfinder/sources/threatcrowd"
	"subfinder/libsubfinder/sources/virustotal"
	"subfinder/libsubfinder/sources/netcraft"
)


func PassiveDiscovery(state *helper.State) (finalPassiveSubdomains []string) {

	// TODO : Add Selection for search sources
	fmt.Printf("\n\n[-] Searching For Subdomains in Crt.sh")
	fmt.Printf("\n[-] Searching For Subdomains in Certspotter")
	fmt.Printf("\n[-] Searching For Subdomains in Threatcrowd")
	fmt.Printf("\n[-] Searching For Subdomains in Findsubdomains")
	fmt.Printf("\n[-] Searching For Subdomains in Hackertarget")
	fmt.Printf("\n[-] Searching For Subdomains in Virustotal")
	fmt.Printf("\n[-] Searching For Subdomains in Netcraft\n")

	ch := make(chan helper.Result, 7)

	// Create goroutines for added speed and recieve data via channels
	go crtsh.Query(state, ch)
	go certspotter.Query(state, ch)
	go hackertarget.Query(state, ch)
	go findsubdomains.Query(state, ch)
	go threatcrowd.Query(state, ch)
	go virustotal.Query(state, ch)
	go netcraft.Query(state, ch)

	// recieve data from all goroutines running
	for i := 1; i <= 7; i++ {
		result := <-ch

		if result.Error != nil {
			// some error occured
			fmt.Printf("\nerror: %v\n", result.Error)
		}
		for _, subdomain := range result.Subdomains {
			finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
		}
	}

	// Now remove duplicate items from the slice
	uniquePassiveSubdomains := helper.Unique(finalPassiveSubdomains)
	// Now, validate all subdomains found
	validPassiveSubdomains := helper.Validate(state, uniquePassiveSubdomains)

	fmt.Printf("\n\n[#] Total %d Unique subdomains found passively\n\n", len(validPassiveSubdomains))
	for _, subdomain := range validPassiveSubdomains {
		fmt.Println(subdomain)
	}

	return finalPassiveSubdomains
}
