.PHONY: all build-darwin-arm64 build-linux-amd64 build-windows-amd64 test clean run install-deps

all: build-darwin-arm64 build-linux-amd64 build-windows-amd64 test

build-darwin-arm64:
	mkdir -p bin
	GOOS=darwin GOARCH=arm64 go build -o bin/iqfetch-darwin-arm64 ./

build-linux-amd64:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -o bin/iqfetch-linux-amd64 ./

build-windows-amd64:
	mkdir -p bin
	GOOS=windows GOARCH=amd64 go build -o bin/iqfetch-windows-amd64.exe ./

test:
	go test ./... -v

clean:
	rm -rf bin

run:
	go run ./

install-deps:
	go mod tidy
	go mod download
