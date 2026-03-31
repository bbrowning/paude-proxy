# Build stage
FROM golang:1.23 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /auth-proxy ./cmd/auth-proxy/

# Runtime stage
FROM quay.io/centos/centos:stream10

# dnsmasq for DNS forwarding (needed by tools like Rust reqwest on internal networks)
# curl for health checks
RUN dnf install -y dnsmasq curl && dnf clean all

# tini for zombie reaping and signal forwarding
ADD https://github.com/krallin/tini/releases/download/v0.19.0/tini /usr/local/bin/tini
RUN chmod +x /usr/local/bin/tini

COPY --from=builder /auth-proxy /usr/local/bin/auth-proxy
COPY entrypoint.sh /usr/local/bin/paude-entrypoint.sh
RUN chmod +x /usr/local/bin/paude-entrypoint.sh

# Writable directories for OpenShift arbitrary UIDs
RUN mkdir -p /data/ca /tmp && chmod 777 /data/ca /tmp
# dnsmasq needs writable pid directory
RUN mkdir -p /run/dnsmasq && chmod 777 /run/dnsmasq

EXPOSE 3128

ENTRYPOINT ["/usr/local/bin/tini", "--", "/usr/local/bin/paude-entrypoint.sh"]
