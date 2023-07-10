# Build
FROM golang:1.20.4-alpine AS build-env
RUN apk add build-base
WORKDIR /app
COPY . /app
WORKDIR /app/v2
RUN go mod download
RUN go build ./cmd/subfinder

# Release
FROM alpine:3.18.0
RUN apk upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /app/v2/subfinder /usr/local/bin/

ENTRYPOINT ["subfinder"]