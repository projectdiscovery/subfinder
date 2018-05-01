# iron/go:dev is the alpine image with the go tools added
FROM iron/go:dev
WORKDIR /app

# Set an env var that matches your github repo name
ENV SRC_DIR=/go/src/github.com/Ice3man543/subfinder/

# Add the source code:
ADD . $SRC_DIR

# Build it:
RUN cd $SRC_DIR; go build -o main; cp main /app/

ENTRYPOINT ["./main"]
CMD ["-h"]
