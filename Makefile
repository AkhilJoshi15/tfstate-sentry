.PHONY: build test test-race fmt fmt-check vet check-version scan-demo clean

BINARY := bin/tfstate-sentry
RELEASE_VERSION := $(shell cat VERSION)
VERSION ?= $(RELEASE_VERSION)-dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/AkhilJoshi15/tfstate-sentry/internal/buildinfo.Version=$(VERSION) \
	-X github.com/AkhilJoshi15/tfstate-sentry/internal/buildinfo.Commit=$(COMMIT) \
	-X github.com/AkhilJoshi15/tfstate-sentry/internal/buildinfo.Date=$(BUILD_DATE)

build:
	mkdir -p bin
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/tfstate-sentry

test:
	go test ./...

test-race:
	go test -race ./...

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

fmt-check:
	test -z "$$(gofmt -l .)"

vet:
	go vet ./...

check-version:
	sh scripts/check-version.sh

scan-demo: build
	$(BINARY) scan --schema testdata/schema/provider-schema.json --fail-on none testdata/show-plan/unsafe.plan.json

clean:
	rm -rf bin dist
