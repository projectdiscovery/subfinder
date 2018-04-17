# SubFinder
[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Twitter](https://img.shields.io/badge/twitter-@Ice3man543-blue.svg)](https://twitter.com/Ice3man543)
[![Twitter](https://img.shields.io/badge/twitter-@codingo__-blue.svg)](https://twitter.com/codingo_)

SubFinder is a subdomain discovery tool that uses various techniques to discover massive amounts of subdomains for any target. It has been aimed as a successor to the [sublist3r project](https://github.com/aboul3la/Sublist3r). SubFinder uses Passive Sources, Search Engines, Pastebins, Internet Archives, etc to find subdomains and then it uses a permutation module inspired by altdns to generate permutations and resolve them quickly using a powerful bruteforcing engine. It can also perform plain bruteforce if needed. The tool is highly customizable, and the code is built with a modular approach in mind making it easy to add functionalities and remove errors.

![SubFinder CLI Options](https://github.com/codingo/codingo.github.io/blob/master/assets/subfinder.png)

## Why?

This project began it's life as a Bug Bounty World slack channel discussion. We (@ice3man & @codingo) were talking about how the cornerstone subdomain tool at the time, sublist3r, appeared to have been abandoned. The goal of this project was to make a low dependancy, manageable project in Go that would continue to be maintained over time. I (@Ice3man) decided to rewrite the sublist3r project and posted about it. @codingo offered to contribute to the project and subfinder was born. 

So finally after working hard, here is something that I hope you guys will :heart:.

## Features

- Simple and modular code base making it easy to contribute.
- Fast And Powerful Bruteforcing Module (In Development)
- Powerful Permutation generation engine. (In Development)
- Many Passive Data Sources (CertDB, CertSpotter, crtsh, DNSDumpster, FindSubdomains, Hackertarget, Netcraft, PassiveTotal, PTRArchive, SecurityTrails, Threatcrowd, VirusTotal)
- Internet Archives support for finding subdomains (In development)

## Install

The installation is easy. Git clone the repo and run go build.

```bash
go get github.com/ice3man543/subfinder
```
To configure it to work with certain services, you need to have an API key for them. These are the services that do not work without an API key.
- [Virustotal](https://www.virustotal.com/) 
- [Passivetotal](http://passivetotal.org/)
- [SecurityTrails](http://securitytrails.com/)

Put these values in the config.json file and you should be good to go.

> If your $GOPATH is /home/go, make sure to place your config.json file in $GOPATH/bin folder or wherever you have the binary. Otherwise, it will not work. 

## NOTE
This tool is currently in active development. So some features may not work or maybe broken. Please do a PR or create an Issue for any features, suggestions or ideas. Would love to hear from you guys.

## Docker

Git clone the repo, then build and run subfinder in a container with the following commands

- Clone the repo using `git clone https://github.com/ice3man543/subfinder.git`
- Edit your `Dockerfile` to include your API keys
- Build your docker container
```bash
docker build -t subfinder .
```

- After building the container, run the following.
```bash
docker run --rm -it subfinder
```
> The above command is the same as running `-h`

For example, this runs the tool against uber.com and output the results to your host file system:
```bash
docker run --rm -it subfinder -d uber.com > uber.com.txt
```
> Note: `-o uber.com.txt` would output into the docker container, which is deleted once the process finishes, because of the `--rm` segment of the docker command)
