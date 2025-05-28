.PHONY: all clean build test run build-linux build-darwin build-windows build-arm64 build-amd64

VERSION := $(shell ./version.sh)
BUILD_TIME := $(shell date +%FT%T%z)
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

ARCHS := amd64 arm64 386 arm
OS := linux darwin windows

all: clean build

build: build-linux build-darwin build-windows

build-linux: build-linux-amd64 build-linux-arm64 build-linux-386 build-linux-arm

build-darwin: build-darwin-amd64 build-darwin-arm64

build-windows: build-windows-amd64 build-windows-arm64 build-windows-386

build-arm64: build-linux-arm64 build-darwin-arm64 build-windows-arm64

build-amd64: build-linux-amd64 build-darwin-amd64 build-windows-amd64

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-linux-amd64 ./src

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-linux-arm64 ./src

build-linux-386:
	GOOS=linux GOARCH=386 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-linux-386 ./src

build-linux-arm:
	GOOS=linux GOARCH=arm go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-linux-arm ./src

build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-darwin-amd64 ./src

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-darwin-arm64 ./src

build-windows-amd64:
	GOOS=windows GOARCH=amd64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-windows-amd64.exe ./src

build-windows-arm64:
	GOOS=windows GOARCH=arm64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-windows-arm64.exe ./src

build-windows-386:
	GOOS=windows GOARCH=386 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-windows-386.exe ./src

clean:
	@rm -rf packages/
	@rm -f alittleserver

test:
	@chmod +x test.sh
	@./test.sh

run:
	@go run ./src 