# Contributing

## Prerequisites

- Go 1.23+
- [pre-commit](https://pre-commit.com/) (optional, but recommended)

## Setup

```bash
go mod tidy
make install-hooks   # sets up pre-commit (gofmt, go vet, golangci-lint)
```

## Running Tests

```bash
make test              # all tests
make unit-test         # unit tests only (-short -race)
make integration-test  # integration tests only (-race)
```

## Other Checks

```bash
make lint        # go vet
make fmt-check   # verify gofmt formatting
make build       # build binary to bin/paude-proxy
make docker      # build container image with podman
```

## Cutting a Release

Releases are fully automated via GitHub Actions. Push a semver tag to trigger the pipeline:

```bash
git tag v1.2.3
git push origin v1.2.3
```

The [release workflow](.github/workflows/release.yml) will:

1. Lint and run all tests
2. Build binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
3. Build and push multi-arch container images to `quay.io/bbrowning/paude-proxy-go-centos10`
4. Create a GitHub Release with auto-generated notes and the binaries attached

**Stable vs pre-release:** Tags matching `vX.Y.Z` exactly (e.g. `v1.2.3`) are treated as stable releases and update the `latest` container tag. Anything else (e.g. `v1.2.3-rc1`) is marked as a pre-release and does not update `latest`.
