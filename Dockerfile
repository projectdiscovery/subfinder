FROM golang:1.8-onbuild

MAINTAINER Anshuman Bhartiya (anshuman.bhartiya@gmail.com)

ADD wordlists /

ENTRYPOINT ["app"]
