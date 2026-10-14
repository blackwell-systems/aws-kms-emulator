// Package kmstest starts the AWS KMS emulator in-process for Go tests and gives
// back an aws-sdk-go-v2 KMS client pointed at it.
package kmstest

import (
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	awskmsemulator "github.com/blackwell-systems/aws-kms-emulator"
)

// Server is a running in-process emulator.
type Server struct {
	// URL is the endpoint of the emulator, for example "http://127.0.0.1:41233".
	URL string
	// Region is the Region the client signs for. It defaults to the emulator's
	// default Region; if you pass WithRegion to NewServer, set this to match
	// before calling Client.
	Region string

	srv *httptest.Server
}

// NewServer starts an emulator and closes it when the test ends. A failure to
// create the emulator (for example an unreadable state file) fails the test.
func NewServer(tb testing.TB, opts ...awskmsemulator.Option) *Server {
	tb.Helper()
	h, err := awskmsemulator.New(opts...)
	if err != nil {
		tb.Fatalf("kmstest: creating the emulator: %v", err)
	}
	srv := httptest.NewServer(h)
	tb.Cleanup(srv.Close)
	return &Server{URL: srv.URL, Region: awskmsemulator.DefaultRegion, srv: srv}
}

// Close shuts the server down before the test ends, for tests that restart it.
func (s *Server) Close() { s.srv.Close() }

// Client returns a KMS client that talks to the emulator with static dummy
// credentials, signing requests with SigV4 like it would against AWS.
func (s *Server) Client() *kms.Client {
	return kms.New(kms.Options{
		Region:       s.Region,
		BaseEndpoint: aws.String(s.URL),
		Credentials:  credentials.NewStaticCredentialsProvider("AKIAEMULATOR", "emulator-secret", ""),
		HTTPClient:   s.srv.Client(),
		// The emulator never validates signatures, so a retry cannot help and
		// would only hide a failing call behind a slow test.
		RetryMaxAttempts: 1,
	})
}

// Config returns an aws.Config for the emulator, for tests that build other
// clients or want to set their own client options.
func (s *Server) Config() aws.Config {
	return aws.Config{
		Region:       s.Region,
		BaseEndpoint: aws.String(s.URL),
		Credentials:  credentials.NewStaticCredentialsProvider("AKIAEMULATOR", "emulator-secret", ""),
		HTTPClient:   s.srv.Client(),
	}
}
