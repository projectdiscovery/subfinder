FROM alpine:latest

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="Fast passive subdomain enumeration tool."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="subfinder"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/subfinder"

RUN apk upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/subfinder /usr/local/bin/

ENTRYPOINT ["subfinder"]
