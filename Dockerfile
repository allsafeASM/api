# Download nuclei templates
FROM alpine/git:latest AS downloader
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates

# Build for AllSafe ASM Worker
FROM golang:1.24.4-alpine AS builder

# Install build dependencies including libpcap-dev for gopacket
RUN apk add --no-cache git ca-certificates libpcap-dev build-base

# Set working directory
WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies with BuildKit cache mount
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy source code
COPY . .

# Build the application with CGO enabled and BuildKit cache
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -a \
    -ldflags="-w -s" \
    -o api .

# Final stage - Using alpine for runtime dependencies
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libpcap

# Copy binary from builder stage
COPY --from=builder /app/api /api

# Copy nuclei templates from downloader stage
COPY --from=downloader /root/nuclei-templates /root/nuclei-templates

# Expose port (if needed for health checks)
EXPOSE 8080

# Set environment variables
ENV GIN_MODE=release

# Run the application
CMD ["/api"] 
