# Contributing to SubFinder

:+1::tada: First off, Many Thanks for taking the time to contribute! :tada::+1:

The follwing is a document describing the project structure of SubFinder subdomain enumeration tool and teaching you how to contribute to it.

### Project Structure

SubFinder is written in golang. The authors have tried to keep the code as simple and modular as possible. There can be flaws in the golang implementation or there may be many things which have identified that could be done better. Regardless, please
create an issue and we would be more than happy to implement your suggestions. Pull Requests are also very appreciated :+1:.

Core structure of the code is as follows:
```
 subfinder -
           |-/libsubfinder-|-/sources|-/ask
           |-main.go                  -/crtsh
           |-config.json              -/certspotter
```

Comments can be found throughout the majority of the code base explaining functionality of usage.

### Adding new Passive Sources

Adding new passive sources to the tool is very easy. Every passive subdomain data source has it's own subpackge under `subfinder/libsubfinder/sources` package. 

In order to add a new source, just create a new directory. For Example, if we are going to add `example` data source, these are the steps involved:

- Create `subfinder/libsubfinder/sources/example` directory.
- Create a main file for your subpackage. For example, `example.go`.
- Add `package example` to the top of the file as package name.

Passive sources follow a similar convention in SubFinder. Each passive source exports all its functionality through a ```Query``` function.
You can have as many functions in your data source but a main ```Query``` function is mandatory. It takes the current program state which is exported as a ```subfinder/libsubfinder/helper.State``` variable. This contains all of your program state. Another argument it takes is a channel which is of type ```subfinder/libsubfinder/helper.Result```.

This channel will be used to return a type result which contains the results from our current run. The structure is something like this.
```golang
type Result struct {
    Subdomains []string     // Subdomains found
    Error      error        // Any error that has occured
}
```

Each package must import helper package. A template for a basic data source is given in example data source. Feel free to modify it.
After making your changes, open the ```subfinder/libsubfinder/engines/passive/passive.go``` which is the main driver for passive discovery engine.

- Import your example package in that file. `"subfinder/libsubfinder/sources/example"`
- Add a print functions with other printing functions already there ```fmt.Printf("\n[-] Searching For Subdomains in PassiveTotal")`
- Create a goquery for your example `go example.Query(state, ch)```
- Increase number of sources by 1 in argument to buffered chanel and for loop for recieving results.

And you will then have created your own passive package! Feel free to make a Pull Request and we'd be more than happy to add your changes and acknowledge you! :+1:






