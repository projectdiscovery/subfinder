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
	//"subfinder/libsubfinder/sources/dnsdb"
	"subfinder/libsubfinder/sources/threatcrowd"
	"subfinder/libsubfinder/sources/virustotal"
	"subfinder/libsubfinder/sources/netcraft"
)


func PassiveDiscovery(state *helper.State) (finalPassiveSubdomains []string) {

	// TODO : Add Go Concurrency to requests for data sources :-)
	fmt.Printf("\n\n[-] Searching For Subdomains in Crt.sh")
	fmt.Printf("\n[-] Searching For Subdomains in Certspotter")
	fmt.Printf("\n[-] Searching For Subdomains in Threatcrowd")
	fmt.Printf("\n[-] Searching For Subdomains in Hackertarget")
	fmt.Printf("\n[-] Searching For Subdomains in Certspotter")
	fmt.Printf("\n[-] Searching For Subdomains in Virustotal")
	fmt.Printf("\n[-] Searching For Subdomains in Netcraft\n")

	crtSh, err := crtsh.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range crtSh {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	certspotterResults, err := certspotter.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range certspotterResults {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	threatcrowdResults, err := threatcrowd.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range threatcrowdResults {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	hackertargetResults, err := hackertarget.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range hackertargetResults {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	/*fmt.Printf("\n\n[-] Trying DNSDB Domain Search")
	dnsdbResults, err := dnsdb.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range dnsdbResults {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}*/

	virustotalResults, err := virustotal.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range virustotalResults {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	netcraftResults, err := netcraft.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range netcraftResults {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	// Now remove duplicate items from the slice
	unique_passive_subdomains := helper.Unique(finalPassiveSubdomains)
	fmt.Printf("\n\n[#] Total %d Unique subdomains found passively\n\n", len(unique_passive_subdomains))
	for _, subdomain := range unique_passive_subdomains {
		fmt.Println(subdomain)
	}

	return finalPassiveSubdomains
}
