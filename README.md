# SubFinder
[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Twitter](https://img.shields.io/badge/twitter-@Ice3man543-blue.svg)](https://twitter.com/Ice3man543)
[![Twitter](https://img.shields.io/badge/twitter-@codingo__-blue.svg)](https://twitter.com/codingo_)

[![forthebadge](https://forthebadge.com/images/badges/built-with-love.svg)](https://forthebadge.com)

SubFinder is a subdomain discovery tool that uses various techniques to discover massive amounts of subdomains for any target. It has been aimed as a successor to the [sublist3r project](https://github.com/aboul3la/Sublist3r). SubFinder uses Passive Sources, Search Engines, Pastebins, Internet Archives, etc to find subdomains and then it uses a permutation module inspired by altdns to generate permutations and resolve them quickly using a powerful bruteforcing engine. It can also perform plain bruteforce if needed. The tool is highly customizable, and the code is built with a modular approach in mind making it easy to add functionalities and remove errors.

[![asciicast](https://raw.githubusercontent.com/Ice3man543/ice3man543.github.io/master/assets/asciinema.png)](https://asciinema.org/a/177851)

# Why?

This project began it's life as a Bug Bounty World slack channel discussion. We were talking about how the cornerstone subdomain tool at the time, sublist3r, appeared to have been abandoned. The goal of this project was to make a low dependancy, manageable project in Go that would continue to be maintained over time. I decided to rewrite the sublist3r project and posted about it. @codingo offered to contribute to the project and subfinder was born. 

# Features

- Simple and modular code base making it easy to contribute.
- Fast And Powerful Bruteforcing Module 
- Powerful Permutation generation engine. (In Development)
- Many Passive Data Sources (21 At Present)
- Multiple Output formats

> Ask, Baidu, Bing, Censys, CertDB, CertSpotter, CrtSH, DnsDB, DNSDumpster, Entrust CT-Search, FindSubdomains, Hackertarget, Netcraft, PassiveTotal, PTRArchive, Riddler, SecurityTrails, ThreatCrowd, ThreatMiner, Virustotal, WaybackArchive

# Usage

```bash
./subfinder -h 
```
This will display help for the tool. Here are all the switches it supports.

| Flag | Description | Example |
|------|-------------|---------|
| -b   | Use bruteforcing to find subdomains | ./subfinder -d example.com -b |
| -c   | Don't show colored output            | ./subfinder -c |
| -d   | Domain to find subdomains for        | ./subfinder -d example.com |
| -dL  | List of domains to find subdomains for | ./subfinder -dl hosts.txt | 
| -nW  | Remove wildcard subdomains           | ./subfinder -nw |
| -o   | Name of the output file (Optional)   | ./subfinder -o output.txt | 
| -oT  | Write output in Aquatone style JSON format (Required -nW)  | ./subfinder -o output.txt -nw -oA | 
| -oJ  | Write output in JSON format          | ./subfinder -o output.json -oJ |
| -oD  | Output to directory (When using multiple hosts) | ./subfinder -od ~/misc/out/ |
| -r  | Comma-separated list of resolvers to use | ./subfinder -r 8.8.8.8,1.1.1.1 |
| -rL  | File containing list of resolvers to use | ./subfinder -rL resolvers.txt |
| --recursive  | Use recursive subdomain finding (default: true) | ./subfinder --recursive |
| --set-config | Sets a configuration option | ./subfinder --set-config example=something |
| --set-settings | Sets a setting option | ./subfinder --set-settings CensysPages=10 |
| --silent | Show only the subdomains found    | ./subfinder --silent |
| --sources | Comma separated list of sources to use (optional) | ./subfinder --sources threatcrowd,virustotal |
| -t   | Number of concurrent threads (Bruteforce) | ./subfinder -t 10 |
| --timeout | Seconds to wait until quitting connection | ./subfinder --timeout 10 |
| -v | Display verbose output  | ./subfinder -v |
| -w | Wordlist for doing bruteforcing and permutation | ./subfinder -w words.txt | 

# Installation Instructions
## Direct Installation

#### SubFinder requires go1.10+ to install successfully !

The installation is easy. Git clone the repo and run go build.

```bash
go get github.com/Ice3man543/subfinder
```

## Upgrading
If you wish to upgrade the package you can use:
```bash
go get -u github.com/Ice3man543/subfinder
```
## Running in a Docker Container

Git clone the repo, then build and run subfinder in a container with the following commands

- Clone the repo using `git clone https://github.com/Ice3man543/subfinder.git`
- Build your docker container
```bash
docker build -t subfinder .
```

- After building the container, run the following.
```bash
docker run -it subfinder
```
> The above command is the same as running `-h`

***NOTE: Please follow the Post Install steps given after this to correctly configure the tool.***

For example, this runs the tool against uber.com and output the results to your host file system:
```bash
docker run -v $HOME/.config/subfinder:/root/.config/subfinder -it subfinder -d uber.com > uber.com.txt
```

## Post Installation Instructions

Subfinder will work after using the installation instructions however to configure Subfinder to work with certain services, you will need to have setup API keys. These following services do not work without an API key:

- [Virustotal](https://www.virustotal.com/) 
- [Passivetotal](http://passivetotal.org/)
- [SecurityTrails](http://securitytrails.com/)
- [Censys](https://censys.io)
- [Riddler](https://riddler.io)

These are the configuration options you have to specify via the command line.
```bash
VirustotalAPIKey 
PassivetotalUsername 
PassivetotalKey
SecurityTrailsKey
RiddlerEmail
RiddlerPassword
CensysUsername
CensysSecret
```

Theses values are stored in the $HOME/.config/subfinder/config.json file which will be created when you run the tool for the first time. To configure the services to use an API key, you need to use the tool with --set-config option which will allow you to set a configuration option. For example:

```bash
./subfinder --set-config VirustotalAPIKey=0x41414141
./subfinder --set-config PassivetotalUsername=hacker,PassivetotalKey=supersecret
```

If you are using docker, you need to first create your directory structure holding subfinder configuration file. You can either run the binary in your host system and let it create the directory structure of files, after which you can use --set-config flag to set the api values like before. Or you can run:
```bash
mkdir $HOME/.config/subfinder
cp config.json $HOME/.config/subfinder/config.json
nano $HOME/.config/subfinder/config.json
```
After that, you can pass it as a volume using the following sample command.
```bash
sudo docker run -v $HOME/.config/subfinder:/root/.config/subfinder -it subfinder -d freelancer.com
```
Now, you can also pass --set-config inside the docker to change the configuration options.

# Running the tool

To run the tool on a target, just use the following command.
```bash
./subfinder -d freelancer.com
```
This will run the tool against freelancer.com. There are a number of configuration options that you can pass along with this command. The verbose switch (-v) can be used to display verbose information.

```bash
[CERTSPOTTER] www.fi.freelancer.com
[DNSDUMPSTER] hosting.freelancer.com
[DNSDUMPSTER] support.freelancer.com
[DNSDUMPSTER] accounts.freelancer.com
[DNSDUMPSTER] phabricator.freelancer.com
[DNSDUMPSTER] cdn1.freelancer.com
[DNSDUMPSTER] t1.freelancer.com
[DNSDUMPSTER] wdc.t1.freelancer.com
[DNSDUMPSTER] dal.t1.freelancer.com
```

The -o command can be used to specify an output file.

```bash
./subfinder -d freelancer.com -o output.txt
```

You can also get output in json format using -oJ switch.
The --silent switch can be used to show only subdomains found without any other info.
The --set-config switch can be used to set the value of any configuration option as explained above in the readme.

You can also pass some special settings for the tool through the command line by using --set-setting flag.
For example, you can pass the number of Censys pages to check using the following command.
```bash
./subfinder -d freelancer.com --sources censys --set-settings CensysPages=2 -v 
```
For checking all pages returned by censys, you can use "all" option. Note, It is a string.

These are the settings currently supported 
```bash
CensysPages
AskPages
BaiduPages
BingPages
```

For using bruteforcing capabilities, you can use -b flag with -w option to specify a wordlist.
```bash
./subfinder -d freelancer.com -b -w jhaddix_all.txt -t 100 --sources censys --set-settings CensysPages=2 -v 
```

You can also write output in JSON format as used by Aquatone.
```bash
./subfinder -d freelancer.com -o result_aquatone.json -oA -nW -v 
```

You can specify custom resolvers too.
```bash
./subfinder -d freelancer.com -o result_aquatone.json -oA -nW -v -r 8.8.8.8,1.1.1.1
./subfinder -d freelancer.com -o result_aquatone.json -oA -nW -v -rL resolvers.txt
```

# Frequently Asked Questions (FAQ)
## How do I move settings between machines?
Configuration for subfinder is saved at ```~/.config/subfinder/config.json``` which can be copied between machines.

## Do I need to use API keys?
No. The majority of sources for subfinder don't require API keys, you just won't see as many results. Check the post installation instructions for which sources require API keys.

## I wish SubFinder did x...
We're extremely open to pull requests, if you wish to have a feature feel free to develop it and push it to here for review and inclusion in the main project. If you're unable to code something, please raise it as an issue and if we think it has benefit to the community we'll look into developing it for you.

## Why is this a better tool than xyz tool?
There are a number of subdomain tools, and we beleive you should try each of them to find the one that works well with how you like to approach subdomain discovery. We've developed subfinder to solve subdomain finding in a way that we felt worked best for the way we work, and was easily maintainable to allow us and others to add as many sources and features as possible.

# Acknowledgements

- @FranticFerret for his work on adding docker support.
- @himanshudas for adding DnsDB support
- @Mzack9999 for fixing and improving docker builds and adding Ask, Baidu, Bing Search Engine Support !
