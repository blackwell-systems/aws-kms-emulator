# Dockerfile for AWS KMS Emulator
# Multi-stage build: compile in the Go image, run from a minimal one.
#
#   docker build -t aws-kms-emulator .
#   docker run -p 8080:8080 aws-kms-emulator

# Build stage
FROM golang:1.27-alpine AS builder

WORKDIR /build

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o server ./cmd/server

# Final stage - minimal image
FROM alpine:latest

WORKDIR /app

COPY --from=builder /build/server .

EXPOSE 8080

# Run as non-root user for security. /data is where AWS_KMS_DATA_DIR usually
# points; it is created here so a volume mounted on it is writable by kmsmock.
RUN addgroup -g 1000 kmsmock && \
    adduser -D -u 1000 -G kmsmock kmsmock && \
    mkdir -p /data && \
    chown -R kmsmock:kmsmock /app /data

USER kmsmock

ENV AWS_KMS_LOG_LEVEL=info

LABEL org.opencontainers.image.title="AWS KMS Emulator"
LABEL org.opencontainers.image.description="Local implementation of the AWS KMS signing API"
LABEL org.opencontainers.image.source="https://github.com/blackwell-systems/aws-kms-emulator"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["/app/server"]
