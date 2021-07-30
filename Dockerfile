# Build
FROM golang:1.16.6-alpine AS build-env
RUN GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder

# Release
FROM alpine:latest
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /go/bin/subfinder /usr/local/bin/subfinder

ENTRYPOINT ["subfinder"]
