//
// Contains color constants for printing
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package helper

// Use like this
// 	fmt.Printf("[%sCRTSH%s] %s", r, rs, subdomain)
var (
	Red    = "\033[31;1;4m" // red color
	Cyan   = "\033[36;6;2m" // cyan color
	Green  = "\033[32;6;3m" // Green color
	Yellow = "\033[0;33m"
	Reset  = "\033[0m" // reset for default color

	Info = "\033[33;1;1m"
	Que  = "\033[34;1;1m"
	Bad  = "\033[31;1;1m"
	Good = "\033[32;1;1m"
	Run  = "\033[97;1;1m"
)
