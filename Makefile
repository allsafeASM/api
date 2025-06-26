.PHONY: build run test clean help deps

# Default target
help:
	@echo "Available targets:"
	@echo "  build       - Build the application"
	@echo "  run         - Run the application"
	@echo "  test        - Run tests"
	@echo "  clean       - Clean build artifacts"
	@echo "  deps        - Download dependencies"

# Build target
build:
	@echo "Building AllSafe ASM worker..."
	@mkdir -p bin
	go build -o bin/allsafe-asm main.go

# Run target
run:
	@echo "Running AllSafe ASM worker..."
	go run main.go

# Development targets
test:
	@echo "Running tests..."
	go test ./...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/

deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Docker target
docker-build:
	@echo "Building Docker image..."
	docker build -t allsafe-asm .

# Development with hot reload (requires air: go install github.com/cosmtrek/air@latest)
dev:
	@echo "Running with hot reload..."
	air -c .air.toml 