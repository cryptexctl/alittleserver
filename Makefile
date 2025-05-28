.PHONY: all clean build test run build-linux build-darwin build-windows build-arm64 build-amd64

VERSION := $(shell git rev-parse --short HEAD)
BUILD_TIME := $(shell date +%FT%T%z)

all: clean build

build: build-linux build-darwin build-windows

build-linux: build-linux-amd64 build-linux-arm64 build-linux-386 build-linux-arm

build-darwin: build-darwin-amd64 build-darwin-arm64

build-windows: build-windows-amd64 build-windows-arm64 build-windows-386

build-arm64: build-linux-arm64 build-darwin-arm64 build-windows-arm64

build-amd64: build-linux-amd64 build-darwin-amd64 build-windows-amd64

build-linux-amd64:
	@mkdir -p packages
	GOOS=linux GOARCH=amd64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-linux-amd64 ./src

build-linux-arm64:
	@mkdir -p packages
	GOOS=linux GOARCH=arm64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-linux-arm64 ./src

build-linux-386:
	@mkdir -p packages
	GOOS=linux GOARCH=386 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-linux-386 ./src

build-linux-arm:
	@mkdir -p packages
	GOOS=linux GOARCH=arm go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-linux-arm ./src

build-darwin-amd64:
	@mkdir -p packages
	GOOS=darwin GOARCH=amd64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-darwin-amd64 ./src

build-darwin-arm64:
	@mkdir -p packages
	GOOS=darwin GOARCH=arm64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-darwin-arm64 ./src

build-windows-amd64:
	@mkdir -p packages
	GOOS=windows GOARCH=amd64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-windows-amd64.exe ./src

build-windows-arm64:
	@mkdir -p packages
	GOOS=windows GOARCH=arm64 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-windows-arm64.exe ./src

build-windows-386:
	@mkdir -p packages
	GOOS=windows GOARCH=386 go build -ldflags="-X 'main.cfg.Version=$(VERSION)'" -o packages/alittleserver-windows-386.exe ./src

clean:
	@rm -rf packages/
	@rm -f alittleserver

test:
	@chmod +x test.sh
	@./test.sh

run:
	@go run ./src 