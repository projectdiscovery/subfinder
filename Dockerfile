# Build
FROM golang:1.18.0-alpine AS build-env
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Release
FROM alpine:3.15.0
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /go/bin/subfinder /usr/local/bin/subfinder

ENTRYPOINT ["subfinder"]
