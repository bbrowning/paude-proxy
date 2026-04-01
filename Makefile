.PHONY: build test unit-test integration-test lint fmt-check clean docker

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
	go vet ./...

fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Files need formatting:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

clean:
	rm -rf bin/

docker:
	podman build -t $(IMAGE) .

run: build
	./bin/$(BINARY)
