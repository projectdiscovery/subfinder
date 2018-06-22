FROM golang:latest
WORKDIR /app

# Set an env var that matches your github repo name
ENV SRC_DIR=/go/src/github.com/Ice3man543/subfinder/

# Add the source code:
ADD libsubfinder ${SRC_DIR}/libsubfinder
ADD main.go ${SRC_DIR}/main.go

# Build it:
RUN cd $SRC_DIR; go get; go build -o main; cp main /app/

COPY wordlists/ ./wordlists/

ENTRYPOINT ["./main"]

