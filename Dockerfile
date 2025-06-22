# Build stage: use Go 1.24.x (use gotip if 1.24 is not yet available on Docker Hub)
FROM golang:1.24.4-alpine AS builder

WORKDIR /app

# Cache dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the Go binary from the main.go in cmd directory
RUN go build -o api ./cmd/main.go

# Production stage: minimal image
FROM alpine:3.19

WORKDIR /app

# Copy the built binary from builder
COPY --from=builder /app/api .

# Expose the default port (change if your app uses a different one)
EXPOSE 8080

# Run the binary
ENTRYPOINT ["./api"]
