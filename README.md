<h1 align="center">
  <img src="static/subfinder-logo.png" alt="subfinder" width="200px"></a>
  <br>
</h1>

<h4 align="center">Fast passive subdomain enumeration tool.</h4>


<p align="center">
<a href="https://goreportcard.com/report/github.com/projectdiscovery/subfinder"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/subfinder"></a>
<a href="https://github.com/projectdiscovery/subfinder/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/projectdiscovery/subfinder/releases"><img src="https://img.shields.io/github/release/projectdiscovery/subfinder"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>
      
<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Install</a> •
  <a href="#running-subfinder">Usage</a> •
  <a href="#post-installation-instructions">API Setup</a> •
  <a href="#subfinder-go-library">Library</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

---


Subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources. It has a simple modular architecture and is optimized for speed. subfinder is built for doing one thing only - passive subdomain enumeration, and it does that very well.

We have designed subfinder to comply with all passive sources licenses, and usage restrictions, as well as maintained a consistently passive model to make it useful to both penetration testers and bug bounty hunters alike.


# Features

<h1 align="left">
  <img src="static/subfinder-run.png" alt="subfinder" width="700px"></a>
  <br>
</h1>


 - Fast and powerful resolution and wildcard elimination module
 - **Curated** passive sources to maximize results
 - Multiple Output formats supported (Json, File, Stdout)
 - Optimized for speed, very fast and **lightweight** on resources
 - **STDIN/OUT** support for integrating in workflows


# Usage

```sh
subfinder -h
```
This will display help for the tool. Here are all the switches it supports.

| Flag             | Description                                                | Example                                     |
| ---------------- | ---------------------------------------------------------- | --------------------------------------------|
| -all             | Use all sources (slow) for enumeration                     | subfinder -d uber.com -all                  |
| -b               | IP address to be used as local bind                        | subfinder -b 172.16.0.1                |
| -config          | Configuration file for API Keys, etc                       | subfinder -config config.yaml               |
| -d               | Domain to find subdomains for                              | subfinder -d uber.com                       |
| -dL              | File containing list of domains to enumerate               | subfinder -dL hackerone-hosts.txt           |
| -exclude-sources | List of sources to exclude from enumeration                | subfinder -exclude-sources archiveis        |
| -max-time        | Minutes to wait for enumeration results (default 10)       | subfinder -max-time 1                       |
| -nC              | Don't Use colors in output                                 | subfinder -nC                               |
| -nW              | Remove Wildcard & Dead Subdomains from output              | subfinder -nW                               |
| -ls              | List all available sources                                 | subfinder -ls                               |
| -o               | File to write output to (optional)                         | subfinder -o output.txt                     |
| -oD              | Directory to write enumeration results to (optional)       | subfinder -oD ~/outputs                     |
| -oI              | Write output in Host,IP format                             | subfinder -oI                               |
| -oJ              | Write output in JSON lines Format                          | subfinder -oJ                               |
| -r               | Comma-separated list of resolvers to use                   | subfinder -r 1.1.1.1,1.0.0.1                |
| -rL              | Text file containing list of resolvers to use              | subfinder -rL resolvers.txt                 |
| -recursive       | Enumeration recursive subdomains                           | subfinder -d news.yahoo.com -recursive      |
| -silent          | Show only subdomains in output                             | subfinder -silent                           |
| -sources         | Comma separated list of sources to use                     | subfinder -sources shodan,censys            |
| -t               | Number of concurrent goroutines for resolving (default 10) | subfinder -t 100                            |
| -timeout         | Seconds to wait before timing out (default 30)             | subfinder -timeout 30                       |
| -proxy           | HTTP proxy to use with subfinder                           | subfinder -proxy http://localhost:3128      |
| -rate-limit      | Maximum number of HTTP requests to send per second         | subfinder -rate-limit 10                    |
| -v               | Show Verbose output                                        | subfinder -v                                |
| -version         | Show current program version                               | subfinder -version                          |


# Installation

Subfinder requires **go1.17** to install successfully. Run the following command to get the repo -

```sh
go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```


## Post Installation Instructions

Subfinder will work after using the installation instructions however to configure Subfinder to work with certain services, you will need to have setup API keys. The following services do not work without an API key:

[Binaryedge](https://binaryedge.io), [C99](https://api.c99.nl/), [Certspotter](https://sslmate.com/certspotter/api/), [Chinaz](http://my.chinaz.com/ChinazAPI/DataCenter/MyDataApi), [Censys](https://censys.io), [Chaos](https://chaos.projectdiscovery.io), [DnsDB](https://api.dnsdb.info), [Fofa](https://fofa.so/static_pages/api_help), [Github](https://github.com), [Intelx](https://intelx.io), [Passivetotal](http://passivetotal.org), [Recon.dev](https://recon.dev), [Robtex](https://www.robtex.com/api/), [SecurityTrails](http://securitytrails.com), [Shodan](https://shodan.io), [Spyse](https://spyse.com), [Threatbook](https://x.threatbook.cn/en), [Virustotal](https://www.virustotal.com), [Zoomeye](https://www.zoomeye.org)

Theses values are stored in the `$HOME/.config/subfinder/config.yaml` file which will be created when you run the tool for the first time. The configuration file uses the YAML format. Multiple API keys can be specified for each of these services from which one of them will be used for enumeration.

For sources that require multiple keys, namely `Censys`, `Passivetotal`, they can be added by separating them via a colon (:).

An example config file -

```yaml
resolvers:
  - 1.1.1.1
  - 1.0.0.1
sources:
  - binaryedge
  - bufferover
  - censys
  - passivetotal
  - sitedossier
binaryedge:
  - 0bf8919b-aab9-42e4-9574-d3b639324597
  - ac244e2f-b635-4581-878a-33f4e79a2c13
censys:
  - ac244e2f-b635-4581-878a-33f4e79a2c13:dd510d6e-1b6e-4655-83f6-f347b363def9
certspotter: []
passivetotal:
  - sample-email@user.com:sample_password
securitytrails: []
shodan:
  - AAAAClP1bJJSRMEYJazgwhJKrggRwKA
github:
  - d23a554bbc1aabb208c9acfbd2dd41ce7fc9db39
  - asdsd54bbc1aabb208c9acfbd2dd41ce7fc9db39
```

# Running Subfinder

To run the tool on a target, just use the following command.

```sh
subfinder -d hackerone.com

               __    _____           __         
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /    
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/ v2.4.9

		projectdiscovery.io

Use with caution. You are responsible for your actions
Developers assume no liability and are not responsible for any misuse or damage.
By using subfinder, you also agree to the terms of the APIs used.

[INF] Enumerating subdomains for hackerone.com

www.hackerone.com
support.hackerone.com
links.hackerone.com
api.hackerone.com
o1.email.hackerone.com
go.hackerone.com
3d.hackerone.com
resources.hackerone.com
a.ns.hackerone.com
b.ns.hackerone.com
mta-sts.hackerone.com
docs.hackerone.com
mta-sts.forwarding.hackerone.com
gslink.hackerone.com
hackerone.com
info.hackerone.com
mta-sts.managed.hackerone.com
events.hackerone.com

[INF] Found 18 subdomains for hackerone.com in 3 seconds 672 milliseconds
```

The subdomains discovered can be piped to other tools too. For example, you can pipe the subdomains discovered by subfinder to httpx [httpx](https://github.com/projectdiscovery/httpx) which will then find running http servers on the host.

```sh
echo hackerone.com | subfinder -silent | httpx -silent

http://hackerone.com
http://www.hackerone.com
http://docs.hackerone.com
http://api.hackerone.com
https://docs.hackerone.com
http://mta-sts.managed.hackerone.com
```

If your enterprise uses source routing to choose network output, or your computer has many public network interfaces (eg: public Wi-Fi + 4G connection + Ethernet Wire + VPN), you might want to choose your output network by binding IP source. In this case, you can use `-b` option.
In the example below, we have 3 network interfaces able to communicate to the Internet through 3 different outputs. Each output is chosen by binding one source IP with `-b` option.

```console
ip addr

[...]
3: wlp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether e8:b1:fc:50:90:a0 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.87/24 brd 192.168.1.255 scope global dynamic noprefixroute wlp3s0
       valid_lft 62538sec preferred_lft 62538sec
4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 100
    link/none
    inet 192.168.254.70 peer 192.168.254.69/32 scope global tun0
       valid_lft forever preferred_lft forever
5: enx0c5b8f279a64: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 0c:5b:8f:a5:63:25 brd ff:ff:ff:ff:ff:ff
    inet 192.168.8.100/24 brd 192.168.8.255 scope global dynamic noprefixroute enx0c5b8f279a64
       valid_lft 86396sec preferred_lft 86396sec
```

```sh
subfinder -d hackerone.com -b 192.168.1.87
```

<table>
<tr>
<td>  

## Subfinder with docker

Pull the latest tagged [subfinder](https://hub.docker.com/r/projectdiscovery/subfinder) docker image:

```sh
docker pull projectdiscovery/subfinder:latest
```

Running subfinder using docker image:

```sh
docker -t projectdiscovery/subfinder:latest -d hackerone.com
```

Running subfinder using docker image with local config file:

```sh
docker run -v $HOME/.config/subfinder:/root/.config/subfinder -t projectdiscovery/subfinder -d hackerone.com
```

</td>
</tr>
</table>

<table>
<tr>
<td>  

## Subfinder Go library

Usage example:

```go
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func main() {
	config := runner.ConfigFile{
		// Use the default list of resolvers by marshaling it to the config
		Resolvers: resolve.DefaultResolvers,
		// Use the default list of passive sources
		Sources: passive.DefaultSources,
		// Use the default list of all passive sources
		AllSources: passive.DefaultAllSources,
		// Use the default list of recursive sources
		Recursive: passive.DefaultRecursiveSources,
	}

	runnerInstance, err := runner.NewRunner(&runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		YAMLConfig:         config,
	})

	buf := bytes.Buffer{}
	err = runnerInstance.EnumerateSingleDomain(context.Background(), "projectdiscovery.io", []io.Writer{&buf})
	if err != nil {
		log.Fatal(err)
	}

	data, err := ioutil.ReadAll(&buf)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", data)
}
```

</td>
</tr>
</table>

### Resources

- [Recon with Me !!!](https://dhiyaneshgeek.github.io/bug/bounty/2020/02/06/recon-with-me/)

# License

subfinder is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/subfinder/blob/master/THANKS.md)** file for more details.

Read the disclaimer for usage at [DISCLAIMER.md](https://github.com/projectdiscovery/subfinder/blob/master/DISCLAIMER.md) and [contact us](mailto:contact@projectdiscovery.io) for any API removal.
