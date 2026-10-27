BINARY  := certpilot
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo dev)
LDFLAGS := -s -w -X main.Version=$(VERSION)

.PHONY: all build fmt vet test clean release bundle linux-amd64 linux-arm64

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test ./...

linux-amd64:
	@mkdir -p dist/stage-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/stage-amd64/certpilot .

linux-arm64:
	@mkdir -p dist/stage-arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/stage-arm64/certpilot .

# 生成 GitHub Release 用的压缩包（每个包含一个 certpilot 二进制）
release: linux-amd64 linux-arm64
	cd dist/stage-amd64 && tar czf ../certpilot-linux-amd64.tar.gz certpilot
	cd dist/stage-arm64 && tar czf ../certpilot-linux-arm64.tar.gz certpilot
	@ls -lh dist/certpilot-linux-*.tar.gz

# 生成离线安装包（解压后 sudo ./install.sh 即可）
bundle: linux-amd64
	rm -rf dist/bundle && mkdir -p dist/bundle
	cp install.sh uninstall.sh README.md dist/bundle/
	cp dist/stage-amd64/certpilot dist/bundle/
	cd dist && tar czf certpilot-offline-amd64.tar.gz -C bundle .
	@echo "离线包: dist/certpilot-offline-amd64.tar.gz"

clean:
	rm -rf dist $(BINARY) $(BINARY).exe
