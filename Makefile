.PHONY: build test lint clean docker

BINARY := paude-proxy
IMAGE := paude-proxy:latest

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/$(BINARY) ./cmd/paude-proxy/

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -rf bin/

docker:
	podman build -t $(IMAGE) .

run: build
	./bin/$(BINARY)
