BINARY  := bw-secrets-agent
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build install clean test lint

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/bw-secrets-agent

install:
	go install $(LDFLAGS) ./cmd/bw-secrets-agent

clean:
	rm -f $(BINARY)

test:
	go test ./...

lint:
	golangci-lint run ./...
