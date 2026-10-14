// AWS KMS Emulator Server
//
// A lightweight emulator of the AWS KMS API for local testing. It speaks the
// AWS JSON 1.1 protocol over HTTP, so the AWS SDKs and the AWS CLI reach it
// when pointed at a custom endpoint, and it needs no AWS credentials.
//
// Usage:
//
//	server --port 8080
//
// Environment Variables:
//
//	AWS_KMS_PORT         - Port to listen on (default: 8080)
//	AWS_KMS_LOG_LEVEL    - Log level: debug, info, warn, error (default: info)
//	AWS_KMS_DATA_DIR     - Directory to persist state in across restarts (default: unset, in-memory only)
//	AWS_KMS_REGION       - Region in ARNs (default: us-east-1)
//	AWS_KMS_ACCOUNT_ID   - Account ID in ARNs (default: 111122223333)
//	AWS_KMS_STRICT_AUTH  - "true" to require a well-formed SigV4 Authorization header (default: off)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	awskmsemulator "github.com/blackwell-systems/aws-kms-emulator"
)

var (
	port     = flag.Int("port", getEnvInt("AWS_KMS_PORT", 8080), "Port to listen on")
	logLevel = flag.String("log-level", getEnv("AWS_KMS_LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
	version  = "0.1.0"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "AWS KMS Emulator v%s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: server [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment Variables:\n")
		fmt.Fprintf(os.Stderr, "  AWS_KMS_PORT             HTTP port (default: 8080)\n")
		fmt.Fprintf(os.Stderr, "  AWS_KMS_LOG_LEVEL        Log level: debug, info, warn, error (default: info)\n")
		fmt.Fprintf(os.Stderr, "  AWS_KMS_DATA_DIR         Directory to persist state in across restarts (default: unset, in-memory only)\n")
		fmt.Fprintf(os.Stderr, "  AWS_KMS_REGION           Region in ARNs (default: %s)\n", awskmsemulator.DefaultRegion)
		fmt.Fprintf(os.Stderr, "  AWS_KMS_ACCOUNT_ID       Account ID in ARNs (default: %s)\n", awskmsemulator.DefaultAccountID)
		fmt.Fprintf(os.Stderr, "  AWS_KMS_STRICT_AUTH      \"true\" to require a well-formed SigV4 Authorization header (default: off)\n")
	}
	flag.Parse()

	log.Printf("AWS KMS Emulator v%s", version)
	log.Printf("Starting on port %d with log level: %s", *port, *logLevel)
	if dataDir := os.Getenv(awskmsemulator.DataDirEnv); dataDir != "" {
		log.Printf("Persisting state to: %s", dataDir)
	}

	opts := awskmsemulator.FromEnv()
	if *logLevel == "debug" {
		opts = append(opts, awskmsemulator.WithLogf(log.Printf))
	}
	handler, err := awskmsemulator.New(opts...)
	if err != nil {
		log.Fatalf("Failed to create KMS server: %v", err)
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("Server listening at %s", srv.Addr)
		log.Printf("Ready to accept connections")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Shutdown: %v", err)
	}
	log.Println("Server stopped")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
	}
	return defaultValue
}
