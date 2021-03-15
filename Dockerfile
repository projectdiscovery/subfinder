FROM golang:1.16.2-alpine AS build-env
RUN GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder

FROM alpine:latest
COPY --from=build-env /go/bin/subfinder /usr/local/bin/subfinder
ENTRYPOINT ["subfinder"]
