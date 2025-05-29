.PHONY: all clean build test run build-linux build-darwin build-windows build-arm64 build-amd64 compress help debug release

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"
BUILD_TIME := $(shell date +%FT%T%z)

# Флаги сборки
RELEASE_FLAGS := -ldflags "-s -w -X main.Version=$(VERSION)"
DEBUG_FLAGS := -gcflags "all=-N -l" -ldflags "-X main.Version=$(VERSION)"

all: clean build

build: build-linux build-darwin build-windows

build-linux: build-linux-amd64 build-linux-arm64 build-linux-386 build-linux-arm

build-darwin: build-darwin-amd64 build-darwin-arm64

build-windows: build-windows-amd64 build-windows-arm64 build-windows-386

build-arm64: build-linux-arm64 build-darwin-arm64 build-windows-arm64

build-amd64: build-linux-amd64 build-darwin-amd64 build-windows-amd64

build-linux-amd64:
	@mkdir -p packages
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o packages/alittleserver-linux-amd64 ./src

build-linux-arm64:
	@mkdir -p packages
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o packages/alittleserver-linux-arm64 ./src

build-linux-386:
	@mkdir -p packages
	GOOS=linux GOARCH=386 go build $(LDFLAGS) -o packages/alittleserver-linux-386 ./src

build-linux-arm:
	@mkdir -p packages
	GOOS=linux GOARCH=arm go build $(LDFLAGS) -o packages/alittleserver-linux-arm ./src

build-darwin-amd64:
	@mkdir -p packages
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o packages/alittleserver-darwin-amd64 ./src

build-darwin-arm64:
	@mkdir -p packages
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o packages/alittleserver-darwin-arm64 ./src

build-windows-amd64:
	@mkdir -p packages
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o packages/alittleserver-windows-amd64.exe ./src

build-windows-arm64:
	@mkdir -p packages
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o packages/alittleserver-windows-arm64.exe ./src

build-windows-386:
	@mkdir -p packages
	GOOS=windows GOARCH=386 go build $(LDFLAGS) -o packages/alittleserver-windows-386.exe ./src

# Релизная сборка (без отладочной информации)
release: clean
	@echo "Building release version..."
	@mkdir -p packages
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			if [ "$$os" = "windows" ]; then \
				ext=".exe"; \
			else \
				ext=""; \
			fi; \
			echo "Building $$os/$$arch..."; \
			GOOS=$$os GOARCH=$$arch go build $(RELEASE_FLAGS) -o packages/alittleserver-$$os-$$arch$$ext ./src; \
		done; \
	done

# Отладочная сборка (с отладочной информацией)
debug: clean
	@echo "Building debug version..."
	@mkdir -p packages
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			if [ "$$os" = "windows" ]; then \
				ext=".exe"; \
			else \
				ext=""; \
			fi; \
			echo "Building $$os/$$arch..."; \
			GOOS=$$os GOARCH=$$arch go build $(DEBUG_FLAGS) -o packages/alittleserver-$$os-$$arch$$ext ./src; \
		done; \
	done

clean:
	@rm -rf packages/
	@rm -f alittleserver

test:
	@chmod +x test.sh
	@./test.sh

run:
	@go run ./src 

compress:
	@if command -v upx >/dev/null 2>&1; then \
		for file in packages/*; do \
			echo "Compressing $$file with UPX..."; \
			upx --best --lzma $$file; \
		done \
	else \
		echo "UPX not found. Please install UPX first."; \
		exit 1; \
	fi

help:
	@echo "Available targets:"
	@echo "  all      - Clean and build"
	@echo "  clean    - Remove build artifacts"
	@echo "  build    - Build for current platform"
	@echo "  release  - Build optimized release version (stripped, no debug info)"
	@echo "  debug    - Build with debug information"
	@echo "  compress - Compress binaries with UPX"
	@echo "  test     - Run tests"
	@echo "  help     - Show this help message" 