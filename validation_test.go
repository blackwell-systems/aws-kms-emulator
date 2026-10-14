package awskmsemulator_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// signErrorCase is one Sign call that must fail with a given error code. The
// rules come from the Sign API reference; see docs/AWS-BEHAVIOUR.md.
type signErrorCase struct {
	name string
	in   func(p256, ed, rsa string) *kms.SignInput
	code string
}

func TestSign_ErrorTypes(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	p256 := *createKey(t, c, types.KeySpecEccNistP256).KeyId
	ed := *createKey(t, c, types.KeySpecEccNistEdwards25519).KeyId
	rsaKey := *createKey(t, c, types.KeySpecRsa2048).KeyId
	sym, err := c.CreateKey(ctx, &kms.CreateKeyInput{})
	if err != nil {
		t.Fatalf("CreateKey (symmetric): %v", err)
	}

	msg := []byte("m")
	ecdsa256 := types.SigningAlgorithmSpecEcdsaSha256
	digest32 := sha256.Sum256(msg)

	cases := []signErrorCase{
		{"empty KeyId", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: aws.String(""), Message: msg, SigningAlgorithm: ecdsa256}
		}, "ValidationException"},
		{"KeyId longer than 2048", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: aws.String(strings.Repeat("a", 2049)), Message: msg, SigningAlgorithm: ecdsa256}
		}, "ValidationException"},
		{"empty Message", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: []byte{}, SigningAlgorithm: ecdsa256}
		}, "ValidationException"},
		{"RAW Message of 4097 bytes", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: make([]byte, 4097), MessageType: types.MessageTypeRaw, SigningAlgorithm: ecdsa256}
		}, "ValidationException"},
		{"Ed25519 RAW Message of 4097 bytes", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &e, Message: make([]byte, 4097), SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512}
		}, "ValidationException"},
		{"unknown SigningAlgorithm", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: msg, SigningAlgorithm: "ECDSA_SHA_999"}
		}, "ValidationException"},
		{"unknown MessageType", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: msg, MessageType: "HASHED", SigningAlgorithm: ecdsa256}
		}, "ValidationException"},
		{"EXTERNAL_MU on an ECC key", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: make([]byte, 64), MessageType: types.MessageTypeExternalMu, SigningAlgorithm: ecdsa256}
		}, "ValidationException"},
		{"DIGEST 31 bytes for SHA-256", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: digest32[:31], MessageType: types.MessageTypeDigest, SigningAlgorithm: ecdsa256}
		}, "ValidationException"},
		{"DIGEST 33 bytes for SHA-256", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: append(digest32[:], 0), MessageType: types.MessageTypeDigest, SigningAlgorithm: ecdsa256}
		}, "ValidationException"},
		{"DIGEST 32 bytes for SHA-512 RSA", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &r, Message: digest32[:], MessageType: types.MessageTypeDigest, SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha512}
		}, "ValidationException"},
		{"Ed25519 with DIGEST", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &e, Message: make([]byte, 64), MessageType: types.MessageTypeDigest, SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512}
		}, "ValidationException"},
		{"Ed25519ph with RAW", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &e, Message: make([]byte, 64), MessageType: types.MessageTypeRaw, SigningAlgorithm: types.SigningAlgorithmSpecEd25519PhSha512}
		}, "ValidationException"},
		{"Ed25519ph without MessageType", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &e, Message: make([]byte, 64), SigningAlgorithm: types.SigningAlgorithmSpecEd25519PhSha512}
		}, "ValidationException"},
		{"Ed25519ph DIGEST of 32 bytes", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &e, Message: digest32[:], MessageType: types.MessageTypeDigest, SigningAlgorithm: types.SigningAlgorithmSpecEd25519PhSha512}
		}, "ValidationException"},
		{"ECDSA_SHA_384 on a P-256 key", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha384}
		}, "InvalidKeyUsageException"},
		{"RSA algorithm on an ECC key", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha256}
		}, "InvalidKeyUsageException"},
		{"ECDSA algorithm on an Ed25519 key", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &e, Message: msg, SigningAlgorithm: ecdsa256}
		}, "InvalidKeyUsageException"},
		{"Ed25519 algorithm on a P-256 key", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512}
		}, "InvalidKeyUsageException"},
		{"ECDSA algorithm on an RSA key", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &r, Message: msg, SigningAlgorithm: ecdsa256}
		}, "InvalidKeyUsageException"},
		{"symmetric ENCRYPT_DECRYPT key", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: sym.KeyMetadata.KeyId, Message: msg, SigningAlgorithm: ecdsa256}
		}, "InvalidKeyUsageException"},
		{"SM2DSA", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecSm2dsa}
		}, "InvalidKeyUsageException"},
		{"ML_DSA_SHAKE_256 on an ECC key", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: &p, Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecMlDsaShake256}
		}, "InvalidKeyUsageException"},
		{"unknown key ID", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: aws.String("1234abcd-12ab-34cd-56ef-1234567890ab"), Message: msg, SigningAlgorithm: ecdsa256}
		}, "NotFoundException"},
		{"unknown alias", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: aws.String("alias/missing"), Message: msg, SigningAlgorithm: ecdsa256}
		}, "NotFoundException"},
		{"unknown alias ARN", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: aws.String("arn:aws:kms:us-east-1:111122223333:alias/missing"), Message: msg, SigningAlgorithm: ecdsa256}
		}, "NotFoundException"},
		{"key ARN in another Region", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: aws.String("arn:aws:kms:eu-west-1:111122223333:key/" + p), Message: msg, SigningAlgorithm: ecdsa256}
		}, "NotFoundException"},
		{"key ARN in another account", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: aws.String("arn:aws:kms:us-east-1:999999999999:key/" + p), Message: msg, SigningAlgorithm: ecdsa256}
		}, "NotFoundException"},
		{"malformed ARN", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: aws.String("arn:aws:kms:us-east-1"), Message: msg, SigningAlgorithm: ecdsa256}
		}, "InvalidArnException"},
		{"ARN of another service", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: aws.String("arn:aws:s3:::bucket/key"), Message: msg, SigningAlgorithm: ecdsa256}
		}, "InvalidArnException"},
		{"ARN of a non-key resource", func(p, e, r string) *kms.SignInput {
			return &kms.SignInput{KeyId: aws.String("arn:aws:kms:us-east-1:111122223333:grant/abc"), Message: msg, SigningAlgorithm: ecdsa256}
		}, "InvalidArnException"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Sign(ctx, tc.in(p256, ed, rsaKey))
			wantCode(t, err, tc.code)
		})
	}
}

func TestSign_MessageSizeBoundary(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	if _, err := c.Sign(ctx, &kms.SignInput{
		KeyId: key.KeyId, Message: bytes.Repeat([]byte{7}, 4096), SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	}); err != nil {
		t.Fatalf("a 4096-byte RAW message must be accepted: %v", err)
	}
}

func TestVerify_ErrorTypes(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	alg := types.SigningAlgorithmSpecEcdsaSha256
	signed, err := c.Sign(ctx, &kms.SignInput{KeyId: key.KeyId, Message: []byte("m"), SigningAlgorithm: alg})
	if err != nil {
		t.Fatal(err)
	}
	sig := signed.Signature
	good := func() *kms.VerifyInput {
		return &kms.VerifyInput{KeyId: key.KeyId, Message: []byte("m"), Signature: sig, SigningAlgorithm: alg}
	}
	cases := map[string]struct {
		mutate func(*kms.VerifyInput)
		code   string
	}{
		"empty Signature":                   {func(in *kms.VerifyInput) { in.Signature = []byte{} }, "ValidationException"},
		"Signature of 6145 bytes":           {func(in *kms.VerifyInput) { in.Signature = make([]byte, 6145) }, "ValidationException"},
		"Message of 4097 bytes":             {func(in *kms.VerifyInput) { in.Message = make([]byte, 4097) }, "ValidationException"},
		"unknown MessageType":               {func(in *kms.VerifyInput) { in.MessageType = "X" }, "ValidationException"},
		"DIGEST of the wrong length":        {func(in *kms.VerifyInput) { in.MessageType = types.MessageTypeDigest }, "ValidationException"},
		"incompatible algorithm":            {func(in *kms.VerifyInput) { in.SigningAlgorithm = types.SigningAlgorithmSpecEcdsaSha384 }, "InvalidKeyUsageException"},
		"unknown key":                       {func(in *kms.VerifyInput) { in.KeyId = aws.String("alias/nope") }, "NotFoundException"},
		"invalid signature":                 {func(in *kms.VerifyInput) { in.Message = []byte("n") }, "KMSInvalidSignatureException"},
		"signature of Ed25519 length noise": {func(in *kms.VerifyInput) { in.Signature = make([]byte, 64) }, "KMSInvalidSignatureException"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := good()
			tc.mutate(in)
			_, err := c.Verify(ctx, in)
			wantCode(t, err, tc.code)
		})
	}
}

// A key that is not Enabled cannot sign, verify or give out its public key,
// except that a Disabled key still returns its public key.
func TestKeyStateGatesCryptoOperations(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	alg := types.SigningAlgorithmSpecEd25519Sha512
	key := createKey(t, c, types.KeySpecEccNistEdwards25519)
	signed, err := c.Sign(ctx, &kms.SignInput{KeyId: key.KeyId, Message: []byte("m"), SigningAlgorithm: alg})
	if err != nil {
		t.Fatal(err)
	}
	verifyIn := &kms.VerifyInput{KeyId: key.KeyId, Message: []byte("m"), Signature: signed.Signature, SigningAlgorithm: alg}
	signIn := &kms.SignInput{KeyId: key.KeyId, Message: []byte("m"), SigningAlgorithm: alg}

	if _, err := c.DisableKey(ctx, &kms.DisableKeyInput{KeyId: key.KeyId}); err != nil {
		t.Fatalf("DisableKey: %v", err)
	}
	_, err = c.Sign(ctx, signIn)
	var disabled *types.DisabledException
	if !errors.As(err, &disabled) {
		t.Fatalf("Sign on a disabled key: %v, want *types.DisabledException", err)
	}
	_, err = c.Verify(ctx, verifyIn)
	wantCode(t, err, "DisabledException")
	if _, err := c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyId}); err != nil {
		t.Fatalf("GetPublicKey on a disabled key must succeed (key-state table): %v", err)
	}

	if _, err := c.EnableKey(ctx, &kms.EnableKeyInput{KeyId: key.KeyId}); err != nil {
		t.Fatalf("EnableKey: %v", err)
	}
	if _, err := c.Sign(ctx, signIn); err != nil {
		t.Fatalf("Sign after EnableKey: %v", err)
	}

	if _, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: key.KeyId}); err != nil {
		t.Fatalf("ScheduleKeyDeletion: %v", err)
	}
	_, err = c.Sign(ctx, signIn)
	wantCode(t, err, "KMSInvalidStateException")
	_, err = c.Verify(ctx, verifyIn)
	wantCode(t, err, "KMSInvalidStateException")
	_, err = c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyId})
	wantCode(t, err, "KMSInvalidStateException")

	// Canceling the deletion leaves the key Disabled, not Enabled.
	if _, err := c.CancelKeyDeletion(ctx, &kms.CancelKeyDeletionInput{KeyId: key.KeyId}); err != nil {
		t.Fatalf("CancelKeyDeletion: %v", err)
	}
	_, err = c.Sign(ctx, signIn)
	wantCode(t, err, "DisabledException")
}
