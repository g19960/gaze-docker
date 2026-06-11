.PHONY: build build-linux build-mac build-mac-arm run

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>NUL || echo unknown)
BUILD_TIME ?= $(shell powershell -NoProfile -Command "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')")
LDFLAGS = -s -w -X main.buildVersion=$(VERSION) -X main.buildCommit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

build:
	go build -ldflags="$(LDFLAGS)" -o gaze-docker .

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o gaze-docker-linux-amd64 .

build-mac:
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o gaze-docker-darwin-amd64 .

build-mac-arm:
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o gaze-docker-darwin-arm64 .

run:
	go run -ldflags="$(LDFLAGS)" .
