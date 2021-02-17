FROM golang:1.14-alpine AS build-env
MAINTAINER Ice3man (nizamul@projectdiscovery.io)
RUN GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder

FROM alpine:latest
COPY --from=build-env /go/bin/subfinder /usr/local/bin/
ENTRYPOINT ["subfinder"]
