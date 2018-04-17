# iron/go:dev is the alpine image with the go tools added
FROM iron/go:dev
WORKDIR /app

# Set an env var that matches your github repo name
ENV SRC_DIR=/go/src/github.com/ice3man543/subfinder/

# Add the source code:
ADD . $SRC_DIR

# Build it:
RUN cd $SRC_DIR; go build -o main; cp main /app/

# Add blank config.json to directory, add your API keys between "" before building
RUN echo -e '{"virustotalApikey":"","passivetotalUsername":"","passivetotalKey":"","securitytrailsKey":""}' > /app/config.json

ENTRYPOINT ["./main"]
CMD ["-h"]
