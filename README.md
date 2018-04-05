# SubFinder

SubFinder is a subdomain discovery tool that uses various techniques to discover massive amount of subdomains for any target. It has been aimed as a successor to the sublist3r project. Since the initial commit, the project has been aimed with speed and efficiency in mind. SubFinder uses Passive Sources, Search Engines, Pastebins, Internet Archives, etc to find subdomains and then it uses a permutation module inspired by altdns to generate permutations and resolved them at a great speed using a powerful bruteforcing engine. It can also perform plain bruteforce if needed. The tool is highly customizable and the code is built with modular approach making it easy to add functionalities and remove errors.



## Why ?

This project began it's life as a Bug Bounty World slack channel discussion. We (@ice3man & @codingo) were talking the channel about How sublist3r has been abandoned and the code is buggy, etc. I (@Ice3man) decided to rewrite the whole project and posted about it. @codingo asked to contribute to the project and I am happy that I let him contribute. 

- The sublist3r code-base is old and dirty :-(
- The other forks are decent but somewhere not that suitable for regular use.
- Amass is awesome and pretty badass but the code has bad structure and is hard to read. Also, we had inconsistent and somewhat shocking results using the tool.

So finally after working hard, here is something that I hope you guys will :heart:.



## Features

- Passive discovery using many different services.

  - [x] Crt.sh

  - [x] Threatcrowd

  - [x] Certspotter

  - [x] Netcraft

  - [x] Hackertarget

  - [x] Virustotal

  - [ ] Ask

    ​

- Powerful Permutation Engine 

- Powerful Bruteforcing and resolving engines.

- Search Engine Support for subdomain discovery.

  ​