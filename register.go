package awskmsemulator

import (
	"net/http"
	"os"
	"time"

	"github.com/blackwell-systems/aws-kms-emulator/internal/server"
	"github.com/blackwell-systems/aws-kms-emulator/internal/storage"
)

// Environment variables the standalone server (and FromEnv) read.
const (
	// DataDirEnv names the directory the emulator keeps its state in.
	DataDirEnv = "AWS_KMS_DATA_DIR"
	// RegionEnv sets the Region that appears in ARNs.
	RegionEnv = "AWS_KMS_REGION"
	// AccountIDEnv sets the account ID that appears in ARNs.
	AccountIDEnv = "AWS_KMS_ACCOUNT_ID"
	// StrictAuthEnv, when "true" or "1", enables strict authorization checks.
	StrictAuthEnv = "AWS_KMS_STRICT_AUTH"
)

// Defaults for the Region and account ID in ARNs.
const (
	DefaultRegion    = storage.DefaultRegion
	DefaultAccountID = storage.DefaultAccountID
)

// Option configures the emulator.
type Option func(*options)

type options struct {
	store  storage.Config
	strict bool
	logf   func(format string, args ...any)
}

// WithDataDir persists keys, aliases and tags in dir (as state.json) and
// restores them on start. The file holds private keys in plaintext: use it
// for development keys only.
func WithDataDir(dir string) Option { return func(o *options) { o.store.DataDir = dir } }

// WithRegion sets the Region that appears in key and alias ARNs.
// Default: DefaultRegion.
func WithRegion(region string) Option { return func(o *options) { o.store.Region = region } }

// WithAccountID sets the account ID that appears in key and alias ARNs.
// Default: DefaultAccountID.
func WithAccountID(id string) Option { return func(o *options) { o.store.AccountID = id } }

// WithStrictAuth makes the emulator reject requests that lack a well-formed
// SigV4 Authorization header for the kms service. Signatures are never
// validated, with or without this option.
func WithStrictAuth(strict bool) Option { return func(o *options) { o.strict = strict } }

// WithClock replaces the clock the emulator uses for creation dates and for
// expiring keys scheduled for deletion. It is meant for tests.
func WithClock(now func() time.Time) Option { return func(o *options) { o.store.Now = now } }

// WithLogf sends one log line per request to logf.
func WithLogf(logf func(format string, args ...any)) Option {
	return func(o *options) { o.logf = logf }
}

// FromEnv returns the options the environment variables ask for.
func FromEnv() []Option {
	var opts []Option
	if v := os.Getenv(DataDirEnv); v != "" {
		opts = append(opts, WithDataDir(v))
	}
	if v := os.Getenv(RegionEnv); v != "" {
		opts = append(opts, WithRegion(v))
	}
	if v := os.Getenv(AccountIDEnv); v != "" {
		opts = append(opts, WithAccountID(v))
	}
	if v := os.Getenv(StrictAuthEnv); v == "true" || v == "1" {
		opts = append(opts, WithStrictAuth(true))
	}
	return opts
}

// New returns an http.Handler that serves the KMS API. Each call returns an
// independent emulator with its own keys.
func New(opts ...Option) (http.Handler, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	store, err := storage.New(o.store)
	if err != nil {
		return nil, err
	}
	return server.New(store, server.Options{StrictAuth: o.strict, Logf: o.logf}), nil
}

// Register mounts the KMS API on mux at "/", the path the AWS SDKs post to.
// It does not start a listener: the caller owns the http.Server lifecycle.
func Register(mux *http.ServeMux, opts ...Option) error {
	h, err := New(opts...)
	if err != nil {
		return err
	}
	mux.Handle("/", h)
	return nil
}
