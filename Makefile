APP      := sambaadm
MODULE   := sambaadm
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X sambaadm/internal/version.Version=$(VERSION) -X sambaadm/internal/version.Commit=$(COMMIT) -X sambaadm/internal/version.Date=$(DATE)

.PHONY: build test lint run clean release release-github docker checksums integration

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP) ./cmd/sambaadm

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
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-amd64   ./cmd/sambaadm
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-arm64   ./cmd/sambaadm
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-darwin-amd64  ./cmd/sambaadm
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-darwin-arm64  ./cmd/sambaadm
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-windows-amd64.exe ./cmd/sambaadm

# Linux amd64 + Windows amd64 for GitHub Releases
release-github:
	@mkdir -p dist
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-amd64 ./cmd/sambaadm
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-windows-amd64.exe ./cmd/sambaadm
	$(MAKE) checksums

checksums:
	@cd dist && shasum -a 256 $(APP)-* > SHA256SUMS
	@cat dist/SHA256SUMS

docker:
	docker build -t $(APP):$(VERSION) .

# Optional live Samba DC tests (see testdata/README.md)
integration:
	./testdata/samba/run-integration.sh

# ALT binary RPM, built in ALT p10 userspace. Requires Docker.
RPM_ARCH ?= amd64
RPM_IMAGE ?= sambaadm-rpm-builder:p10
rpm-alt:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=$(RPM_ARCH) go build -trimpath -ldflags "$(LDFLAGS)" -o dist/sambaadm-linux-$(RPM_ARCH) ./cmd/sambaadm
	docker build --platform linux/$(RPM_ARCH) -t $(RPM_IMAGE)-$(RPM_ARCH) -f packaging/alt/Dockerfile .
	docker run --rm --platform linux/$(RPM_ARCH) -v "$(CURDIR):/src" $(RPM_IMAGE)-$(RPM_ARCH) bash packaging/alt/build-rpm.sh $(VERSION) /src/dist/sambaadm-linux-$(RPM_ARCH) /src/dist
	cp deploy/sambaadm-package dist/sambaadm-package
	cp docs/alt-install.md dist/sambaadm-alt-install.md
	$(MAKE) checksums

.PHONY: rpm-alt
