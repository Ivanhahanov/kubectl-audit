BINARY  := kubectl-audit
MODULE  := github.com/ivanhahanov/kubectl-audit
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X '$(MODULE)/internal/cli.Version=$(VERSION)'
GOBIN   ?= $(shell go env GOPATH)/bin

.PHONY: build test vet install clean cross-compile

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/kubectl-audit

test:
	go test ./...

vet:
	go vet ./...

install: build
	mkdir -p $(GOBIN)
	install -m 0755 bin/$(BINARY) $(GOBIN)/$(BINARY)
	@echo "Installed $(GOBIN)/$(BINARY). Verify with: kubectl audit version"

clean:
	rm -rf bin dist

# CGO_ENABLED=0: the tool has no cgo dependencies, and disabling it is what
# makes cross-compiling to other OS/arch combos work from a single host
# without a matching C cross-toolchain.
cross-compile:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64      ./cmd/kubectl-audit
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64      ./cmd/kubectl-audit
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64     ./cmd/kubectl-audit
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64     ./cmd/kubectl-audit
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/kubectl-audit
