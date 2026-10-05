APP      := sambaadm
MODULE   := sambaadm
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X sambaadm/internal/version.Version=$(VERSION) -X sambaadm/internal/version.Commit=$(COMMIT) -X sambaadm/internal/version.Date=$(DATE)

.PHONY: build test lint run clean release release-github docker checksums

build:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(APP) ./cmd/sambaadm

test:
	go test ./...

lint:
	golangci-lint run ./...

run: build
	./bin/$(APP) serve --listen=:8080

clean:
	rm -rf bin dist

release:
	@mkdir -p dist
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-amd64   ./cmd/sambaadm
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-arm64   ./cmd/sambaadm
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(APP)-darwin-amd64  ./cmd/sambaadm
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(APP)-darwin-arm64  ./cmd/sambaadm
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(APP)-windows-amd64.exe ./cmd/sambaadm

# Linux amd64 + Windows amd64 for GitHub Releases
release-github:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-amd64 ./cmd/sambaadm
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(APP)-windows-amd64.exe ./cmd/sambaadm
	$(MAKE) checksums

checksums:
	@cd dist && shasum -a 256 $(APP)-linux-amd64 $(APP)-windows-amd64.exe > SHA256SUMS
	@cat dist/SHA256SUMS

docker:
	docker build -t $(APP):$(VERSION) .
