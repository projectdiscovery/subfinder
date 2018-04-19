//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Contains different functions for reporting
package output

import (
     "io"
     "os"

     "github.com/ice3man543/subfinder/libsubfinder/helper"
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
