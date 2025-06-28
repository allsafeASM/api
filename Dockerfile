# Ultra-minimal build for AllSafe ASM Worker - Optimized for size
# Build stage
FROM golang:1.24.4-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with maximum optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a \
    -ldflags="-w -s -extldflags '-static'" \
    -o api .

# Final stage - Using scratch for absolute minimal size
FROM scratch

# Copy CA certificates for HTTPS connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary from builder stage
COPY --from=builder /app/api /api

# Expose port (if needed for health checks)
EXPOSE 8080

# Set environment variables
ENV GIN_MODE=release

# Run the application
CMD ["/api"] 