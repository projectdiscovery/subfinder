# Build image: golang:1.16.6-alpine3.14
FROM golang@sha256:a8df40ad1380687038af912378f91cf26aeabb05046875df0bfedd38a79b5499 AS build
RUN GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder

## Release image: alpine:3.14.1
FROM alpine@sha256:be9bdc0ef8e96dbc428dc189b31e2e3b05523d96d12ed627c37aa2936653258c

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates

COPY --from=build /go/bin/subfinder /usr/local/bin/subfinder

RUN adduser \
    --gecos "" \
    --disabled-password \
    subfinder

USER subfinder

ENTRYPOINT ["subfinder"]
