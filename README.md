<h1 align="center">
  <img src="static/subfinder-logo.png" alt="subfinder" width="200px">
  <br>
</h1>

<h4 align="center">Fast passive subdomain enumeration tool.</h4>


<p align="center">
<a href="https://goreportcard.com/report/github.com/projectdiscovery/subfinder/v2"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/subfinder"></a>
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


`subfinder` is a subdomain discovery tool that returns valid subdomains for websites, using passive online sources. It has a simple, modular architecture and is optimized for speed. `subfinder` is built for
doing one thing only - passive subdomain enumeration, and it does that very well.

We have made it to comply with all the used passive source licenses and usage restrictions. The passive model guarantees speed and stealthiness that can be leveraged by both penetration testers and bug bounty
hunters alike.

# Features

<h1 align="left">
  <img src="static/subfinder-run.png" alt="subfinder" width="700px"></a>
  <br>
</h1>

- Fast and powerful resolution and wildcard elimination modules
- **Curated** passive sources to maximize results
- Multiple output formats supported (JSON, file, stdout)
- Optimized for speed and **lightweight** on resources
- **STDIN/OUT** support enables easy integration into workflows

# Usage

```sh
subfinder -h
```

This will display help for the tool. Here are all the switches it supports.

```yaml
Usage:
  ./subfinder [flags]

Flags:
INPUT:
  -d, -domain string[]  domains to find subdomains for
  -dL, -list string     file containing list of domains for subdomain discovery

SOURCE:
  -s, -sources string[]           specific sources to use for discovery (-s crtsh,github). Use -ls to display all available sources.
  -recursive                      use only sources that can handle subdomains recursively (e.g. subdomain.domain.tld vs domain.tld)
  -all                            use all sources for enumeration (slow)
  -es, -exclude-sources string[]  sources to exclude from enumeration (-es alienvault,zoomeyeapi)

FILTER:
  -m, -match string[]   subdomain or list of subdomain to match (file or comma separated)
  -f, -filter string[]   subdomain or list of subdomain to filter (file or comma separated)

RATE-LIMIT:
  -rl, -rate-limit int  maximum number of http requests to send per second
  -rls value            maximum number of http requests to send per second four providers in key=value format (-rls "hackertarget=10/s,shodan=15/s")
  -t int                number of concurrent goroutines for resolving (-active only) (default 10)

UPDATE:
   -up, -update                 update subfinder to latest version
   -duc, -disable-update-check  disable automatic subfinder update check

OUTPUT:
  -o, -output string       file to write output to
  -oJ, -json               write output in JSONL(ines) format
  -oD, -output-dir string  directory to write output (-dL only)
  -cs, -collect-sources    include all sources in the output (-json only)
  -oI, -ip                 include host IP in output (-active only)

CONFIGURATION:
  -config string                flag config file (default "$CONFIG/subfinder/config.yaml")
  -pc, -provider-config string  provider config file (default "$CONFIG/subfinder/provider-config.yaml")
  -r string[]                   comma separated list of resolvers to use
  -rL, -rlist string            file containing list of resolvers to use
  -nW, -active                  display active subdomains only
  -proxy string                 http proxy to use with subfinder
  -ei, -exclude-ip              exclude IPs from the list of domains

DEBUG:
  -silent             show only subdomains in output
  -version            show version of subfinder
  -v                  show verbose output
  -nc, -no-color      disable color in output
  -ls, -list-sources  list all available sources

OPTIMIZATION:
  -timeout int   seconds to wait before timing out (default 30)
  -max-time int  minutes to wait for enumeration results (default 10)
```

# Installation

`subfinder` requires **go1.20** to install successfully. Run the following command to install the latest version:

```sh
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Post Installation Instructions

`subfinder` can be used right after the installation, however the following services require configuring API keys to work:

[BeVigil](https://bevigil.com/osint-api), [BinaryEdge](https://binaryedge.io), [BufferOver](https://tls.bufferover.run), [C99](https://api.c99.nl/), [Censys](https://censys.io), [CertSpotter](https://sslmate.com/certspotter/api/), [Chaos](https://chaos.projectdiscovery.io), [Chinaz](http://my.chinaz.com/ChinazAPI/DataCenter/MyDataApi), [DNSDB](https://api.dnsdb.info), [Fofa](https://fofa.info/static_pages/api_help), [FullHunt](https://fullhunt.io), [GitHub](https://github.com), [Intelx](https://intelx.io), [PassiveTotal](http://passivetotal.org), [quake](https://quake.360.cn), [Robtex](https://www.robtex.com/api/), [SecurityTrails](http://securitytrails.com), [Shodan](https://shodan.io), [ThreatBook](https://x.threatbook.cn/en), [VirusTotal](https://www.virustotal.com), [WhoisXML API](https://whoisxmlapi.com/), [ZoomEye](https://www.zoomeye.org), [ZoomEye API](https://api.zoomeye.org), [dnsrepo](https://dnsrepo.noc.org), [Hunter](https://hunter.qianxin.com/), [Facebook](https://developers.facebook.com), [BuiltWith](https://api.builtwith.com/domain-api)

You can also use the `subfinder -ls` command to display all the available sources.

These values are stored in the `$CONFIG/subfinder/provider-config.yaml` file which will be created when you run the tool for the first time. The configuration file uses the YAML format. Multiple API keys
can be specified for each of these services from which one of them will be used for enumeration.

Composite keys for sources like, `Censys`, `PassiveTotal`, `Fofa`, `Intellix` and `360quake`, need to be separated with a colon (`:`).

An example provider config file:

```yaml
binaryedge:
  - 0bf8919b-aab9-42e4-9574-d3b639324597
  - ac244e2f-b635-4581-878a-33f4e79a2c13
censys:
  - ac244e2f-b635-4581-878a-33f4e79a2c13:dd510d6e-1b6e-4655-83f6-f347b363def9
certspotter: []
passivetotal:
  - sample-email@user.com:sample_password
redhuntlabs:
  - ENDPOINT:API_TOKEN
  - https://reconapi.redhuntlabs.com/community/v1/domains/subdomains:joEPzJJp2AuOCw7teAj63HYrPGnsxuPQ
securitytrails: []
shodan:
  - AAAAClP1bJJSRMEYJazgwhJKrggRwKA
github:
  - ghp_lkyJGU3jv1xmwk4SDXavrLDJ4dl2pSJMzj4X
  - ghp_gkUuhkIYdQPj13ifH4KA3cXRn8JD2lqir2d4
zoomeyeapi:
  - 4f73021d-ff95-4f53-937f-83d6db719eec
quake:
  - 0cb9030c-0a40-48a3-b8c4-fca28e466ba3
facebook:
  - APP_ID:APP_SECRET
intelx:
  - HOST:API_KEY
  - 2.intelx.io:s4324-b98b-41b2-220e8-3320f6a1284d
```

Note: RedHunt Labs's [Attack Surface Recon API](https://devportal.redhuntlabs.com/) has different API endpoints depending on the user's subscription. Make sure to add the appropriate endpoint before running any scans.

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

The subdomains discovered can be piped to other tools too. For example, you can pipe the discovered subdomains to [`httpx`](https://github.com/projectdiscovery/httpx) which will then find
running HTTP servers on the host.

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

Running `subfinder` using the docker image:

```sh
docker run projectdiscovery/subfinder:latest -d hackerone.com
```

Running `subfinder` using the docker image, with a local config file:

```sh
docker run -v $CONFIG/subfinder:/root/.config/subfinder -t projectdiscovery/subfinder -d hackerone.com
```

</td>
</tr>
</table>

<table>
<tr>
<td>  

## Subfinder Go library

Subfinder can also be used as library and a minimal examples of using subfinder SDK is available [here](v2/examples/main.go)

</td>
</tr>
</table>

### Resources

- [Recon with Me !!!](https://dhiyaneshgeek.github.io/bug/bounty/2020/02/06/recon-with-me/)

# License

`subfinder` is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See
the **[THANKS.md](https://github.com/projectdiscovery/subfinder/blob/main/THANKS.md)** file for more details.

Read the usage disclaimer at [DISCLAIMER.md](https://github.com/projectdiscovery/subfinder/blob/main/DISCLAIMER.md) and [contact us](mailto:contact@projectdiscovery.io) for any API removal.