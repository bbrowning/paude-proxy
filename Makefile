.PHONY: build test unit-test integration-test lint clean docker install-hooks

BINARY := paude-proxy
IMAGE := paude-proxy:latest

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/$(BINARY) ./cmd/paude-proxy/

test:
	go test ./...

unit-test:
	go test -short -race ./...

integration-test:
	go test -race -run TestIntegration ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

docker:
	podman build -t $(IMAGE) .

install-hooks:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$(go env GOPATH)/bin v2.12.2
	uvx pre-commit install

run: build
	./bin/$(BINARY)
