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

We have designed `subfinder` to comply with all passive sources licenses, and usage restrictions, as well as maintained a consistently passive model to make it useful to both penetration testers and bug bounty hunters alike.


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

```yaml
Flags:
INPUT:
   -d, -domain string[]  domains to find subdomains for
   -dL, -list string     file containing list of domains for subdomain discovery

SOURCE:
   -s, -sources string[]           sources to use for discovery (-s crtsh,github)
   -recursive                      use only recursive sources
   -all                            Use all sources (slow) for enumeration
   -es, -exclude-sources string[]  sources to exclude from enumeration (-es archiveis,zoomeye)

RATE-LIMIT:
   -rl, -rate-limit int  maximum number of http requests to send per second
   -t int                number of concurrent goroutines for resolving (-active only) (default 10)

OUTPUT:
   -o, -output string       file to write output to
   -oJ, -json               write output in JSONL(ines) format
   -oD, -output-dir string  directory to write output (-dL only)
   -cs, -collect-sources    include all sources in the output (-json only)
   -oI, -ip                 include host IP in output (-active only)

CONFIGURATION:
   -config string                flag config file (default "$HOME/.config/subfinder/config.yaml")
   -pc, -provider-config string  provider config file (default "$HOME/.config/subfinder/provider-config.yaml")
   -r string[]                   comma separated list of resolvers to use
   -rL, -rlist string            file containing list of resolvers to use
   -nW, -active                  display active subdomains only
   -proxy string                 http proxy to use with subfinder

DEBUG:
   -ls       list all available sources
   -silent   show only subdomains in output
   -version  show version of subfinder
   -v        show verbose output
   -nc, -no-color      disable color in output

OPTIMIZATION:
   -timeout int   seconds to wait before timing out (default 30)
   -max-time int  minutes to wait for enumeration results (default 10)
```

# Installation

Subfinder requires **go1.17** to install successfully. Run the following command to install the latest version:

```sh
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```


## Post Installation Instructions

Subfinder will work after using the installation instructions however to configure Subfinder to work with certain services, you will need to have setup API keys. The following services do not work without an API key:

[Binaryedge](https://binaryedge.io), [C99](https://api.c99.nl/), [Certspotter](https://sslmate.com/certspotter/api/), [Chinaz](http://my.chinaz.com/ChinazAPI/DataCenter/MyDataApi), [Censys](https://censys.io), [Chaos](https://chaos.projectdiscovery.io), [DnsDB](https://api.dnsdb.info), [Fofa](https://fofa.so/static_pages/api_help), [Github](https://github.com), [Intelx](https://intelx.io), [Passivetotal](http://passivetotal.org), [Robtex](https://www.robtex.com/api/), [SecurityTrails](http://securitytrails.com), [Shodan](https://shodan.io), [Threatbook](https://x.threatbook.cn/en), [Virustotal](https://www.virustotal.com), [Zoomeye](https://www.zoomeye.org)

These values are stored in the `$HOME/.config/subfinder/provider-config.yaml` file which will be created when you run the tool for the first time. The configuration file uses the YAML format. Multiple API keys can be specified for each of these services from which one of them will be used for enumeration.

For sources that require multiple keys, namely `Censys`, `Passivetotal`, they can be added by separating them via a colon (:).

An example provider config file -

```yaml
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
  - ghp_lkyJGU3jv1xmwk4SDXavrLDJ4dl2pSJMzj4X
  - ghp_gkUuhkIYdQPj13ifH4KA3cXRn8JD2lqir2d4
```

# Running Subfinder

To run the tool on a target, just use the following command.

```console
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

```console
echo hackerone.com | subfinder -silent | httpx -silent

http://hackerone.com
http://www.hackerone.com
http://docs.hackerone.com
http://api.hackerone.com
https://docs.hackerone.com
http://mta-sts.managed.hackerone.com
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
docker run projectdiscovery/subfinder:latest -d hackerone.com
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
	"log"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func main() {
	runnerInstance, err := runner.NewRunner(&runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Resolvers:          resolve.DefaultResolvers, // Use the default list of resolvers by marshaling it to the config
		Sources:            passive.DefaultSources, // Use the default list of passive sources
		AllSources:         passive.DefaultAllSources, // Use the default list of all passive sources
		Recursive:          passive.DefaultRecursiveSources,	// Use the default list of recursive sources
		Providers:          &runner.Providers{}, // Use empty api keys for all providers
  })

	buf := bytes.Buffer{}
	err = runnerInstance.EnumerateSingleDomain(context.Background(), "projectdiscovery.io", []io.Writer{&buf})
	if err != nil {
		log.Fatal(err)
	}

	data, err := io.ReadAll(&buf)
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

`subfinder` is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/subfinder/blob/master/THANKS.md)** file for more details.

Read the disclaimer for usage at [DISCLAIMER.md](https://github.com/projectdiscovery/subfinder/blob/master/DISCLAIMER.md) and [contact us](mailto:contact@projectdiscovery.io) for any API removal.
