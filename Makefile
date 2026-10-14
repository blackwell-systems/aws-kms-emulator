.PHONY: help build install test test-coverage vet clean run docker

# Default target
help:
	@echo "AWS KMS Emulator - Build Targets"
	@echo ""
	@echo "Build commands:"
	@echo "  make build          - Build the server to bin/server"
	@echo "  make install        - Install the server to GOPATH/bin"
	@echo "  make run            - Build and run the server on :8080"
	@echo ""
	@echo "Docker commands:"
	@echo "  make docker         - Build the Docker image"
	@echo ""
	@echo "Test commands:"
	@echo "  make test           - Run all tests"
	@echo "  make test-coverage  - Run tests with coverage"
	@echo "  make vet            - go vet for Linux and Windows"
	@echo ""
	@echo "Other commands:"
	@echo "  make clean          - Remove built binaries"

build:
	@echo "Building server..."
	go build -o bin/server ./cmd/server

install:
	@echo "Installing server..."
	go install ./cmd/server

test:
	go test -v ./...

test-coverage:
	go test -v -cover -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

vet:
	go vet ./...
	GOOS=windows go vet ./...

clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

run: build
	./bin/server

docker:
	@echo "Building Docker image..."
	docker build -t aws-kms-emulator:latest .
