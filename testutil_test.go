package awskmsemulator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	awskmsemulator "github.com/blackwell-systems/aws-kms-emulator"
	"github.com/blackwell-systems/aws-kms-emulator/kmstest"
)

// newClient starts an in-process emulator and returns an aws-sdk-go-v2 client
// for it, so every test goes through the same client real applications use.
func newClient(t *testing.T, opts ...awskmsemulator.Option) (*kms.Client, *kmstest.Server) {
	t.Helper()
	srv := kmstest.NewServer(t, opts...)
	return srv.Client(), srv
}

func createKey(t *testing.T, c *kms.Client, spec types.KeySpec) *types.KeyMetadata {
	t.Helper()
	out, err := c.CreateKey(context.Background(), &kms.CreateKeyInput{
		KeySpec:  spec,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		t.Fatalf("CreateKey(%s): %v", spec, err)
	}
	return out.KeyMetadata
}

// errCode returns the AWS error code of err, or "" when err is not an API error.
// ValidationException is not a modeled error in the KMS SDK, so code is the
// uniform way to assert on every error type.
func errCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want %s", code)
	}
	if got := errCode(err); got != code {
		t.Fatalf("error code = %q, want %q (err: %v)", got, code, err)
	}
}
